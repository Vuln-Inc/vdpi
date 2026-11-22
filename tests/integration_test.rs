use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vdpi::config::{CliArgs, DesyncMode};
use vdpi::desync::{EngineContext, LearnedStrategy};
use vdpi::proxy::socks::{encode_socks5_udp_packet, parse_socks5_udp_packet};
use vdpi::server::{bind_listeners, serve_until_shutdown};

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
        let mut proxy = TcpStream::connect(primary_addr).await.unwrap();
        let req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            tls_addr.port(),
            tls_addr.port()
        );
        proxy.write_all(req.as_bytes()).await.unwrap();
        let mut resp = [0u8; 39];
        proxy.read_exact(&mut resp).await.unwrap();
        assert!(std::str::from_utf8(&resp)
            .unwrap()
            .starts_with("HTTP/1.1 200"));

        let sni = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(sni, proxy).await.unwrap();
        tls.write_all(b"ping-over-http-connect").await.unwrap();
        let mut out = Vec::new();
        tls.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"ping-over-http-connect");
    }

    // 2. Test SOCKS5 CONNECT on BOTH dedicated socks_addr AND protocol-autodetected primary_addr
    for endpoint in [socks_addr, primary_addr] {
        let mut proxy = TcpStream::connect(endpoint).await.unwrap();
        proxy.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        proxy.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x00]);

        let mut req = vec![0x05, 0x01, 0x00, 0x03, 9];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&tls_addr.port().to_be_bytes());
        proxy.write_all(&req).await.unwrap();

        let mut reply = [0u8; 10];
        proxy.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        let sni = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(sni, proxy).await.unwrap();
        tls.write_all(b"ping-over-socks5").await.unwrap();
        let mut out = Vec::new();
        tls.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"ping-over-socks5");
    }

    // 3. Test SOCKS4a CONNECT on primary_addr
    {
        let mut proxy = TcpStream::connect(primary_addr).await.unwrap();
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&tls_addr.port().to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]);
        req.push(0x00);
        req.extend_from_slice(b"localhost\0");
        proxy.write_all(&req).await.unwrap();

        let mut rep = [0u8; 8];
        proxy.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x5a);

        let sni = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(sni, proxy).await.unwrap();
        tls.write_all(b"ping-over-socks4a").await.unwrap();
        let mut out = Vec::new();
        tls.read_to_end(&mut out).await.unwrap();
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

    let mut ctrl = TcpStream::connect(socks_addr).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet = [0u8; 2];
    ctrl.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x00]);

    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    ctrl.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00);
    assert_eq!(rep[3], 0x01);
    let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let framed = encode_socks5_udp_packet(echo_addr, b"voice-opus-packet-001");
    client_udp.send_to(&framed, relay_addr).await.unwrap();

    let mut recv_buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client_udp.recv_from(&mut recv_buf),
    )
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
async fn end_to_end_all_five_desync_stages_complete_real_tls_handshake() {
    let host = "chat.discord.test";
    let (tls_addr, cert) = spawn_local_tls_echo_server(host).await;
    let connector = build_tls_client_connector(cert);

    let stages = [
        LearnedStrategy::Primary,
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
            let (client_sock, _) = proxy_listener.accept().await.unwrap();
            let remote_sock = TcpStream::connect(tls_addr).await.unwrap();
            srv_ctx
                .relay_tunnel(client_sock, remote_sock, Some(host), tls_addr)
                .await
                .unwrap();
        });

        let client_tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let sni = ServerName::try_from(host).unwrap();
        let mut tls = connector.connect(sni, client_tcp).await.unwrap();
        let msg = format!("ok-{stage:?}");
        tls.write_all(msg.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, msg.as_bytes());
        drop(tls);
        relay_task.await.unwrap();
    }
}
