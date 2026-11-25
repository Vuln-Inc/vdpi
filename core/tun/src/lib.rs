pub mod config;
pub mod device;
pub mod doctor;
pub mod events;
#[cfg(unix)]
pub mod fd;
pub mod packet;
pub mod pipeline;

use crate::config::TunnelConfig;
use crate::events::EngineEvent;
use crate::pipeline::TunStats;
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;
use vdpi_core::binder::OutboundBinder;
use vdpi_core::desync::EngineContext;

/// Builds an [`EngineContext`] from a mobile [`TunnelConfig`], attaching and pre-loading
/// the persistent adaptive stage cache file whenever `config.cache_path` is provided.
pub async fn build_engine_context(config: TunnelConfig) -> Result<EngineContext> {
    build_engine_context_with_binder(config, None).await
}

/// Builds an [`EngineContext`] from a [`TunnelConfig`] with an optional outbound socket
/// [`OutboundBinder`], attaching and pre-loading the persistent adaptive stage cache file
/// whenever `config.cache_path` is provided.
pub async fn build_engine_context_with_binder(
    config: TunnelConfig,
    binder: Option<Arc<dyn OutboundBinder>>,
) -> Result<EngineContext> {
    let cache_path = config
        .cache_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    let ctx = EngineContext::new_with_binder(config.into_runtime_config(), binder)?;
    if let Some(path) = cache_path {
        ctx.attach_cache_file(path).await;
    }
    Ok(ctx)
}

/// Flushes any attached persistent adaptive stage cache once during clean tunnel stop.
pub async fn flush_engine_cache(ctx: &EngineContext) {
    if let Err(e) = ctx.flush_persisted_cache().await {
        debug!(error = %e, "failed to flush persisted adaptive cache on tunnel stop");
    }
}

/// Unified JSON telemetry payload shared by Android and iOS clients.
#[derive(Debug, Clone, Serialize)]
pub struct TelemetrySnapshot {
    pub running: bool,
    pub uptime_secs: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub tls_handshakes: u64,
    pub auto_heal_escalations: u64,
    pub dns_queries: u64,
    pub quic_blocked: u64,
    pub udp_flows_active: u64,
    pub learned_hosts: usize,
    pub stage_number: u8,
    pub stage_label: String,
    pub dns_addr: String,
    pub doh_enabled: bool,
    pub events: Vec<EngineEvent>,
}

impl TelemetrySnapshot {
    pub fn idle(events: Vec<EngineEvent>) -> Self {
        Self {
            running: false,
            uptime_secs: 0,
            active_connections: 0,
            total_connections: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            tls_handshakes: 0,
            auto_heal_escalations: 0,
            dns_queries: 0,
            quic_blocked: 0,
            udp_flows_active: 0,
            learned_hosts: 0,
            stage_number: 1,
            stage_label: "ComboMultiRecord".to_string(),
            dns_addr: "1.1.1.1".to_string(),
            doh_enabled: true,
            events,
        }
    }

    pub fn from_live(
        ctx: &EngineContext,
        tun_stats: &TunStats,
        started_at: Instant,
        running: bool,
        events: Vec<EngineEvent>,
    ) -> Self {
        let core = ctx.telemetry_snapshot();
        let stage = ctx.preferred_stage();
        Self {
            running,
            uptime_secs: if running {
                started_at.elapsed().as_secs()
            } else {
                0
            },
            active_connections: core.active_connections,
            total_connections: core.total_connections,
            bytes_tx: core.bytes_tx,
            bytes_rx: core.bytes_rx,
            tls_handshakes: core.tls_handshakes,
            auto_heal_escalations: core.auto_heal_escalations,
            dns_queries: ctx.dns.query_count(),
            quic_blocked: tun_stats.quic_blocked.load(Ordering::Relaxed),
            udp_flows_active: tun_stats.udp_flows_active.load(Ordering::Relaxed),
            learned_hosts: core.learned_hosts,
            stage_number: stage.stage_number(),
            stage_label: stage.label().to_string(),
            dns_addr: ctx.config.dns_addr.clone(),
            doh_enabled: ctx.config.enable_doh,
            events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use vdpi_core::binder::NoopBinder;
    use vdpi_core::desync::LearnedStrategy;

    #[tokio::test]
    async fn build_engine_context_with_binder_attaches_outbound_binder() {
        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let ctx_bound = build_engine_context_with_binder(TunnelConfig::default(), Some(binder))
            .await
            .unwrap();
        assert!(ctx_bound.outbound_binder.is_some());

        let ctx_default = build_engine_context(TunnelConfig::default()).await.unwrap();
        assert!(ctx_default.outbound_binder.is_none());
    }

    #[tokio::test]
    async fn build_engine_context_attaches_and_flushes_persisted_cache() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vdpi-tun-cache-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache_file = dir.join("adaptive-cache.json");

        let cfg1 = TunnelConfig {
            cache_path: Some(cache_file.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let ctx1 = build_engine_context(cfg1).await.unwrap();
        assert!(ctx1.has_cache_file().await);
        {
            let mut guard = ctx1.adaptive_cache.write().await;
            guard.insert("discord.com".to_string(), LearnedStrategy::FineFragment);
            ctx1.telemetry
                .learned_hosts
                .store(guard.len(), Ordering::Relaxed);
        }
        ctx1.preferred_isp_stage
            .store(LearnedStrategy::MultiRecordOob as u8, Ordering::Relaxed);
        flush_engine_cache(&ctx1).await;
        assert!(cache_file.exists());

        let cfg2 = TunnelConfig {
            cache_path: Some(cache_file.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let ctx2 = build_engine_context(cfg2).await.unwrap();
        assert_eq!(ctx2.learned_host_count().await, 1);
        assert_eq!(ctx2.telemetry_snapshot().learned_hosts, 1);
        assert_eq!(ctx2.preferred_stage(), LearnedStrategy::MultiRecordOob);
        assert_eq!(
            ctx2.adaptive_cache.read().await.get("discord.com").copied(),
            Some(LearnedStrategy::FineFragment)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
