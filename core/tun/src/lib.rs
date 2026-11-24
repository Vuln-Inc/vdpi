pub mod config;
pub mod doctor;
pub mod events;
#[cfg(unix)]
pub mod fd;
mod packet;
pub mod pipeline;

use crate::events::EngineEvent;
use crate::pipeline::TunStats;
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::time::Instant;
use vdpi::desync::EngineContext;

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
