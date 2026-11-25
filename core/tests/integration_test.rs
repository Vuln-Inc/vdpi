use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vdpi::config::{CliArgs, DesyncMode};
use vdpi::desync::{EngineContext, LearnedStrategy};
use vdpi::proxy::socks::{encode_socks5_udp_packet, parse_socks5_udp_packet};
use vdpi::server::{bind_listeners, serve_until_shutdown};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

async fn read_http_response_headers(stream: &mut TcpStream) -> String {
    const HEADER_END: [u8; 4] = [0x0d, 0x0a, 0x0d, 0x0a];
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while !buf.ends_with(&HEADER_END) {
        let n = tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut byte))
            .await
            .expect("timed out reading HTTP CONNECT response header")
            .expect("failed reading HTTP CONNECT response header");
        assert_ne!(
            n, 0,
            "unexpected EOF before HTTP header terminator: {buf:?}"
        );
        buf.push(byte[0]);
        assert!(
            buf.len() <= 8192,
            "HTTP CONNECT response headers exceeded 8192 bytes"
        );
    }
    String::from_utf8(buf).expect("HTTP CONNECT response headers must be valid UTF-8")
}

async fn spawn_test_vdpi(mode: DesyncMode) -> (SocketAddr, SocketAddr, watch::Sender<bool>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = CliArgs::parse_from_iter([
        "vdpi",
        "--port",
        "0",
        "--socks-port",
        "0",
        "--no-system-proxy",
        "--chunk-size",
        "8",
    ])
    .unwrap();
    let mut cfg = cli.into_runtime_config();
    cfg.socks_port = Some(0);
    cfg.mode = mode;

    let ctx = EngineContext::new(cfg).unwrap();
    let bound = bind_listeners(&ctx).unwrap();
    let http_addr = bound.primary_addr;
    let socks_addr = bound.socks_addr.unwrap();

    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_until_shutdown(bound, ctx, rx).await;
    });

    (http_addr, socks_addr, tx)
}

async fn spawn_local_tls_echo_server(hostname: &str) -> (SocketAddr, CertificateDer<'static>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_key = generate_simple_self_signed(vec![hostname.to_string(), "localhost".to_string()])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(cert_key.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("valid TLS server config");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = tls.read(&mut buf).await {
                        let _ = tls.write_all(&buf[..n]).await;
                        let _ = tls.shutdown().await;
                        // Drain the peer's shutdown before dropping the socket. Windows can
                        // report a TCP reset if the peer's TLS close_notify is still unread.
                        let _ = tls.read(&mut buf).await;
                    }
                }
            });
        }
    });

    (addr, cert_der)
}

fn build_tls_client_connector(cert_der: CertificateDer<'static>) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

#[tokio::test]
async fn end_to_end_http_connect_and_autodetect_socks5_tls_tunnel() {
    let (tls_addr, cert) = spawn_local_tls_echo_server("localhost").await;
    let (primary_addr, socks_addr, stop_tx) = spawn_test_vdpi(DesyncMode::Combo).await;
    let connector = build_tls_client_connector(cert);

    // 1. Test HTTP CONNECT tunnel on primary port
    {
        let mut proxy = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(primary_addr))
            .await
            .expect("timed out connecting to HTTP CONNECT proxy")
            .unwrap();
        let req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\x0d\nHost: 127.0.0.1:{}\x0d\n\x0d\n",
            tls_addr.port(),
            tls_addr.port()
        );
        tokio::time::timeout(TEST_TIMEOUT, proxy.write_all(req.as_bytes()))
            .await
            .expect("timed out writing HTTP CONNECT request")
            .unwrap();
        let resp = read_http_response_headers(&mut proxy).await;
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "unexpected response: {resp:?}"
        );

        let sni = ServerName::try_from("localhost").unwrap();
        let mut tls = tokio::time::timeout(TEST_TIMEOUT, connector.connect(sni, proxy))
            .await
            .expect("timed out completing TLS handshake over HTTP CONNECT")
            .unwrap();
        tokio::time::timeout(TEST_TIMEOUT, tls.write_all(b"ping-over-http-connect"))
            .await
            .expect("timed out writing over HTTP CONNECT TLS")
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(TEST_TIMEOUT, tls.read_to_end(&mut out))
            .await
            .expect("timed out reading over HTTP CONNECT TLS")
            .unwrap();
        assert_eq!(out, b"ping-over-http-connect");
    }

    // 2. Test SOCKS5 CONNECT on BOTH dedicated socks_addr AND protocol-autodetected primary_addr
    for endpoint in [socks_addr, primary_addr] {
        let mut proxy = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(endpoint))
            .await
            .expect("timed out connecting to SOCKS5 endpoint")
            .unwrap();
        tokio::time::timeout(TEST_TIMEOUT, proxy.write_all(&[0x05, 0x01, 0x00]))
            .await
            .expect("timed out writing SOCKS5 greeting")
            .unwrap();
        let mut greet = [0u8; 2];
        tokio::time::timeout(TEST_TIMEOUT, proxy.read_exact(&mut greet))
            .await
            .expect("timed out reading SOCKS5 greeting")
            .unwrap();
        assert_eq!(greet, [0x05, 0x00]);

        let mut req = vec![0x05, 0x01, 0x00, 0x03, 9];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&tls_addr.port().to_be_bytes());
        tokio::time::timeout(TEST_TIMEOUT, proxy.write_all(&req))
            .await
            .expect("timed out writing SOCKS5 CONNECT request")
            .unwrap();

        let mut reply = [0u8; 10];
        tokio::time::timeout(TEST_TIMEOUT, proxy.read_exact(&mut reply))
            .await
            .expect("timed out reading SOCKS5 CONNECT reply")
            .unwrap();
        assert_eq!(reply[1], 0x00);

        let sni = ServerName::try_from("localhost").unwrap();
        let mut tls = tokio::time::timeout(TEST_TIMEOUT, connector.connect(sni, proxy))
            .await
            .expect("timed out completing TLS handshake over SOCKS5")
            .unwrap();
        tokio::time::timeout(TEST_TIMEOUT, tls.write_all(b"ping-over-socks5"))
            .await
            .expect("timed out writing over SOCKS5 TLS")
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(TEST_TIMEOUT, tls.read_to_end(&mut out))
            .await
            .expect("timed out reading over SOCKS5 TLS")
            .unwrap();
        assert_eq!(out, b"ping-over-socks5");
    }

    // 3. Test SOCKS4a CONNECT on primary_addr
    {
        let mut proxy = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(primary_addr))
            .await
            .expect("timed out connecting to SOCKS4a endpoint")
            .unwrap();
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&tls_addr.port().to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]);
        req.push(0x00);
        req.extend_from_slice(b"localhost\0");
        tokio::time::timeout(TEST_TIMEOUT, proxy.write_all(&req))
            .await
            .expect("timed out writing SOCKS4a request")
            .unwrap();

        let mut rep = [0u8; 8];
        tokio::time::timeout(TEST_TIMEOUT, proxy.read_exact(&mut rep))
            .await
            .expect("timed out reading SOCKS4a reply")
            .unwrap();
        assert_eq!(rep[1], 0x5a);

        let sni = ServerName::try_from("localhost").unwrap();
        let mut tls = tokio::time::timeout(TEST_TIMEOUT, connector.connect(sni, proxy))
            .await
            .expect("timed out completing TLS handshake over SOCKS4a")
            .unwrap();
        tokio::time::timeout(TEST_TIMEOUT, tls.write_all(b"ping-over-socks4a"))
            .await
            .expect("timed out writing over SOCKS4a TLS")
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(TEST_TIMEOUT, tls.read_to_end(&mut out))
            .await
            .expect("timed out reading over SOCKS4a TLS")
            .unwrap();
        assert_eq!(out, b"ping-over-socks4a");
    }

    let _ = stop_tx.send(true);
}

#[tokio::test]
async fn end_to_end_socks5_udp_associate_voice_and_game_relay() {
    let (_, socks_addr, stop_tx) = spawn_test_vdpi(DesyncMode::Combo).await;

    let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        if let Ok((n, peer)) = udp_echo.recv_from(&mut buf).await {
            let mut reply = b"ack:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = udp_echo.send_to(&reply, peer).await;
        }
    });

    let mut ctrl = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .expect("timed out connecting to SOCKS5 UDP control socket")
        .unwrap();
    tokio::time::timeout(TEST_TIMEOUT, ctrl.write_all(&[0x05, 0x01, 0x00]))
        .await
        .expect("timed out writing SOCKS5 UDP greeting")
        .unwrap();
    let mut greet = [0u8; 2];
    tokio::time::timeout(TEST_TIMEOUT, ctrl.read_exact(&mut greet))
        .await
        .expect("timed out reading SOCKS5 UDP greeting")
        .unwrap();
    assert_eq!(greet, [0x05, 0x00]);

    tokio::time::timeout(
        TEST_TIMEOUT,
        ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
    )
    .await
    .expect("timed out writing SOCKS5 UDP ASSOCIATE request")
    .unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(TEST_TIMEOUT, ctrl.read_exact(&mut rep))
        .await
        .expect("timed out reading SOCKS5 UDP ASSOCIATE reply")
        .unwrap();
    assert_eq!(rep[1], 0x00);
    assert_eq!(rep[3], 0x01);
    let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let framed = encode_socks5_udp_packet(echo_addr, b"voice-opus-packet-001");
    tokio::time::timeout(TEST_TIMEOUT, client_udp.send_to(&framed, relay_addr))
        .await
        .expect("timed out sending SOCKS5 UDP datagram")
        .unwrap();

    let mut recv_buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), client_udp.recv_from(&mut recv_buf))
        .await
        .unwrap()
        .unwrap();

    let (src_host, _, src_port, payload) = parse_socks5_udp_packet(&recv_buf[..n]).unwrap();
    assert_eq!(src_host, "127.0.0.1");
    assert_eq!(src_port, echo_addr.port());
    assert_eq!(payload, b"ack:voice-opus-packet-001");

    drop(ctrl);
    let _ = stop_tx.send(true);
}

#[tokio::test]
async fn end_to_end_all_seven_desync_stages_complete_real_tls_handshake() {
    let host = "chat.discord.test";
    let (tls_addr, cert) = spawn_local_tls_echo_server(host).await;
    let connector = build_tls_client_connector(cert);

    let stages = [
        LearnedStrategy::Primary,
        LearnedStrategy::OobSniDesync,
        LearnedStrategy::MultiRecordOob,
        LearnedStrategy::FineFragment,
        LearnedStrategy::DeepRecordStorm,
        LearnedStrategy::SlowSniSlice,
        LearnedStrategy::DirectPassthrough,
    ];

    for stage in stages {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--no-system-proxy",
            "--chunk-size",
            "10",
            "--include",
            "discord\\.test$",
        ])
        .unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();
        ctx.preferred_isp_stage
            .store(stage as u8, Ordering::Relaxed);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let srv_ctx = ctx.clone();
        let relay_task = tokio::spawn(async move {
            let (client_sock, _) = tokio::time::timeout(TEST_TIMEOUT, proxy_listener.accept())
                .await
                .expect("timed out accepting stage test connection")
                .unwrap();
            let remote_sock = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(tls_addr))
                .await
                .expect("timed out connecting to local TLS echo server")
                .unwrap();
            tokio::time::timeout(
                TEST_TIMEOUT,
                srv_ctx.relay_tunnel(client_sock, remote_sock, Some(host), tls_addr),
            )
            .await
            .expect("timed out relaying TLS tunnel")
            .unwrap();
        });

        let client_tcp = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(proxy_addr))
            .await
            .expect("timed out connecting stage test client")
            .unwrap();
        let sni = ServerName::try_from(host).unwrap();
        let mut tls = tokio::time::timeout(TEST_TIMEOUT, connector.connect(sni, client_tcp))
            .await
            .expect("timed out completing TLS handshake for stage")
            .unwrap();
        let msg = format!("ok-{stage:?}");
        tokio::time::timeout(TEST_TIMEOUT, tls.write_all(msg.as_bytes()))
            .await
            .expect("timed out writing stage payload")
            .unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(TEST_TIMEOUT, tls.read_to_end(&mut reply))
            .await
            .expect("timed out reading stage reply")
            .unwrap();
        assert_eq!(reply, msg.as_bytes());
        tokio::time::timeout(TEST_TIMEOUT, tls.shutdown())
            .await
            .expect("timed out shutting down stage TLS stream")
            .unwrap();
        drop(tls);
        tokio::time::timeout(TEST_TIMEOUT, relay_task)
            .await
            .expect("timed out waiting for relay_task")
            .unwrap();

        let snap = ctx.telemetry_snapshot();
        assert_eq!(
            snap.auto_heal_escalations, 0,
            "stage {stage:?} must succeed directly without auto-heal escalation"
        );
        assert_eq!(
            snap.tls_handshakes, 1,
            "stage {stage:?} must record exactly one TLS handshake"
        );
        assert_eq!(
            ctx.learned_host_count().await,
            0,
            "stage {stage:?} must not silently learn a fallback host stage"
        );
    }
}
