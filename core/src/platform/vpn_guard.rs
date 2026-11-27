//! Deterministic VPN coexistence and auto-recovery state machine.
//!
//! Coordinates `vdpi` TUN/proxy yielding when a full-tunnel third-party VPN
//! takes over host internet routing, and debounces recovery when the VPN
//! disconnects so server switches or brief reconnects never cause TUN flapping.

use super::vpn::VpnScope;
use std::time::{Duration, Instant};
use vdpi_core::config::VpnCoexistence;

/// Default cooldown after a full-tunnel VPN disappears before resuming TUN.
pub const DEFAULT_RECOVERY_DEBOUNCE: Duration = Duration::from_secs(3);

/// Current lifecycle state of [`VpnGuard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardState {
    /// `vdpi` is active with no full-tunnel VPN yield in effect.
    Active,
    /// `vdpi` has yielded TUN/proxy control to an active full-tunnel VPN.
    YieldedStandby { provider: String, since: Instant },
    /// The full-tunnel VPN has cleared; waiting for the recovery debounce window
    /// to elapse before bringing TUN back up.
    Recovering { since: Instant },
}

/// Action emitted by [`VpnGuard::evaluate`] for the runtime supervisor to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardAction {
    /// No runtime transition required.
    None,
    /// Immediately yield TUN routes/adapter (or conflicting proxy takeover) for `provider`.
    YieldTun { provider: String },
    /// Debounce window elapsed with no full-tunnel VPN; resume TUN / anti-DPI protection.
    ResumeTun,
    /// Policy is `Warn`; keep `vdpi` active and surface a conflict warning for `provider`.
    WarnOnly { provider: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingYield {
    provider: String,
    since: Instant,
}

/// Deterministic state machine governing third-party VPN coexistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnGuard {
    policy: VpnCoexistence,
    state: GuardState,
    recovery_debounce: Duration,
    yield_confirmation: Duration,
    pending_yield: Option<PendingYield>,
    has_observed_active_clear: bool,
}

impl Default for VpnGuard {
    fn default() -> Self {
        Self::new(VpnCoexistence::default())
    }
}

impl VpnGuard {
    /// Creates a new guard using `policy` and [`DEFAULT_RECOVERY_DEBOUNCE`] (3 seconds).
    pub const fn new(policy: VpnCoexistence) -> Self {
        Self::with_recovery_debounce(policy, DEFAULT_RECOVERY_DEBOUNCE)
    }

    /// Creates a new guard with an explicit `recovery_debounce` duration.
    pub const fn with_recovery_debounce(
        policy: VpnCoexistence,
        recovery_debounce: Duration,
    ) -> Self {
        Self {
            policy,
            state: GuardState::Active,
            recovery_debounce,
            yield_confirmation: Duration::ZERO,
            pending_yield: None,
            has_observed_active_clear: false,
        }
    }

    /// Configures an optional confirmation window for mid-session non-kill-switch
    /// full-tunnel detections so transient route flaps do not cause spurious yields.
    /// Startup full-tunnel detections and `kill_switch` full tunnels still yield at 0ms.
    pub fn with_yield_confirmation(mut self, yield_confirmation: Duration) -> Self {
        self.yield_confirmation = yield_confirmation;
        self
    }

    /// Returns the configured VPN coexistence policy.
    pub const fn policy(&self) -> VpnCoexistence {
        self.policy
    }

    /// Returns the current guard state.
    pub const fn state(&self) -> &GuardState {
        &self.state
    }

    /// Returns the configured recovery debounce duration.
    pub const fn recovery_debounce(&self) -> Duration {
        self.recovery_debounce
    }

    /// Returns the configured mid-session yield confirmation duration.
    pub const fn yield_confirmation(&self) -> Duration {
        self.yield_confirmation
    }

    /// Returns `true` while TUN is yielded (`YieldedStandby` or `Recovering`).
    pub const fn is_yielded(&self) -> bool {
        !matches!(self.state, GuardState::Active)
    }

    /// Returns `true` while awaiting mid-session yield confirmation.
    pub const fn is_pending_yield(&self) -> bool {
        self.pending_yield.is_some()
    }

    /// Rolls an `AutoYield` guard back into `Recovering` starting at `now` (e.g., if
    /// resuming TUN failed right after [`GuardAction::ResumeTun`]).
    pub fn rollback_to_recovering_at(&mut self, now: Instant) {
        self.pending_yield = None;
        if matches!(self.policy, VpnCoexistence::AutoYield) {
            self.state = GuardState::Recovering { since: now };
        }
    }

    /// Rolls an `AutoYield` guard back into `Recovering` starting at `Instant::now()`.
    pub fn rollback_to_recovering(&mut self) {
        self.rollback_to_recovering_at(Instant::now());
    }

    /// Advances the state machine using the latest detected [`VpnScope`] and monotonic
    /// timestamp `now`, returning the [`GuardAction`] to apply.
    pub fn evaluate(&mut self, scope: &VpnScope, now: Instant) -> GuardAction {
        match self.policy {
            VpnCoexistence::Off => {
                self.state = GuardState::Active;
                self.pending_yield = None;
                GuardAction::None
            }
            VpnCoexistence::Warn => {
                self.state = GuardState::Active;
                self.pending_yield = None;
                match scope {
                    VpnScope::FullTunnel { provider, .. } => GuardAction::WarnOnly {
                        provider: provider.clone(),
                    },
                    VpnScope::None | VpnScope::SplitOverlay { .. } => GuardAction::None,
                }
            }
            VpnCoexistence::AutoYield => match scope {
                VpnScope::FullTunnel {
                    provider,
                    kill_switch,
                    ..
                } => match &mut self.state {
                    GuardState::YieldedStandby {
                        provider: active_provider,
                        ..
                    } => {
                        self.pending_yield = None;
                        if active_provider != provider {
                            active_provider.clone_from(provider);
                        }
                        GuardAction::None
                    }
                    GuardState::Recovering { .. } => {
                        self.pending_yield = None;
                        self.state = GuardState::YieldedStandby {
                            provider: provider.clone(),
                            since: now,
                        };
                        GuardAction::None
                    }
                    GuardState::Active => {
                        let immediate_yield = self.yield_confirmation.is_zero()
                            || *kill_switch
                            || !self.has_observed_active_clear;
                        if immediate_yield {
                            self.pending_yield = None;
                            self.state = GuardState::YieldedStandby {
                                provider: provider.clone(),
                                since: now,
                            };
                            return GuardAction::YieldTun {
                                provider: provider.clone(),
                            };
                        }

                        let confirmed = self.pending_yield.as_ref().is_some_and(|pending| {
                            pending.provider == *provider
                                && now.saturating_duration_since(pending.since)
                                    >= self.yield_confirmation
                        });
                        if confirmed {
                            self.pending_yield = None;
                            self.state = GuardState::YieldedStandby {
                                provider: provider.clone(),
                                since: now,
                            };
                            GuardAction::YieldTun {
                                provider: provider.clone(),
                            }
                        } else {
                            if self
                                .pending_yield
                                .as_ref()
                                .is_none_or(|pending| pending.provider != *provider)
                            {
                                self.pending_yield = Some(PendingYield {
                                    provider: provider.clone(),
                                    since: now,
                                });
                            }
                            GuardAction::None
                        }
                    }
                },
                VpnScope::None | VpnScope::SplitOverlay { .. } => {
                    self.pending_yield = None;
                    let transition = match &self.state {
                        GuardState::Active => {
                            self.has_observed_active_clear = true;
                            None
                        }
                        GuardState::YieldedStandby { .. } => {
                            if self.recovery_debounce.is_zero() {
                                self.has_observed_active_clear = true;
                                Some((GuardState::Active, GuardAction::ResumeTun))
                            } else {
                                Some((GuardState::Recovering { since: now }, GuardAction::None))
                            }
                        }
                        GuardState::Recovering { since } => {
                            if now.saturating_duration_since(*since) >= self.recovery_debounce {
                                self.has_observed_active_clear = true;
                                Some((GuardState::Active, GuardAction::ResumeTun))
                            } else {
                                None
                            }
                        }
                    };
                    if let Some((next_state, action)) = transition {
                        self.state = next_state;
                        action
                    } else {
                        GuardAction::None
                    }
                }
            },
        }
    }

    /// Returns a human-readable VPN conflict label for `/vdpi-health` (`vpn_conflict`)
    /// and the Control Center status badge, or `None` when clear or disabled.
    pub fn active_conflict_label(&self, scope: &VpnScope) -> Option<String> {
        match self.policy {
            VpnCoexistence::Off => None,
            VpnCoexistence::Warn => scope
                .full_tunnel_provider()
                .map(|provider| format!("{provider} (warn)")),
            VpnCoexistence::AutoYield => match &self.state {
                GuardState::YieldedStandby { provider, .. } => {
                    Some(format!("{provider} (yielded)"))
                }
                GuardState::Recovering { .. } => {
                    if let Some(provider) = scope.full_tunnel_provider() {
                        Some(format!("{provider} (yielded)"))
                    } else {
                        Some("recovering".to_string())
                    }
                }
                GuardState::Active => scope.full_tunnel_provider().map(str::to_string),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_tunnel(provider: &str, iface: &str, kill_switch: bool) -> VpnScope {
        VpnScope::FullTunnel {
            provider: provider.to_string(),
            iface: iface.to_string(),
            kill_switch,
        }
    }

    fn split_overlay(providers: &[&str]) -> VpnScope {
        VpnScope::SplitOverlay {
            providers: providers.iter().copied().map(str::to_string).collect(),
        }
    }

    #[test]
    fn startup_full_tunnel_yields_immediately_at_zero_ms() {
        let t0 = Instant::now();
        let mut guard = VpnGuard::new(VpnCoexistence::AutoYield);
        assert_eq!(guard.policy(), VpnCoexistence::AutoYield);
        assert_eq!(guard.recovery_debounce(), DEFAULT_RECOVERY_DEBOUNCE);
        assert_eq!(guard.state(), &GuardState::Active);
        assert!(!guard.is_yielded());

        let mullvad = full_tunnel("Mullvad", "Mullvad", true);
        let action = guard.evaluate(&mullvad, t0);
        assert_eq!(
            action,
            GuardAction::YieldTun {
                provider: "Mullvad".to_string(),
            }
        );
        assert_eq!(
            guard.state(),
            &GuardState::YieldedStandby {
                provider: "Mullvad".to_string(),
                since: t0,
            }
        );
        assert!(guard.is_yielded());
        assert_eq!(
            guard.active_conflict_label(&mullvad).as_deref(),
            Some("Mullvad (yielded)")
        );

        // Subsequent polls while still in full tunnel do not emit duplicate yields.
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!(guard.evaluate(&mullvad, t1), GuardAction::None);
        assert_eq!(
            guard.state(),
            &GuardState::YieldedStandby {
                provider: "Mullvad".to_string(),
                since: t0,
            }
        );
    }

    #[test]
    fn mid_session_full_tunnel_yields_at_zero_ms_and_tracks_provider_switch() {
        let t0 = Instant::now();
        let mut guard = VpnGuard::new(VpnCoexistence::AutoYield);

        assert_eq!(guard.evaluate(&VpnScope::None, t0), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Active);
        assert_eq!(guard.active_conflict_label(&VpnScope::None), None);

        let t_vpn = t0 + Duration::from_secs(10);
        let wg = full_tunnel("WireGuard", "wg0", false);
        assert_eq!(
            guard.evaluate(&wg, t_vpn),
            GuardAction::YieldTun {
                provider: "WireGuard".to_string(),
            }
        );
        assert_eq!(
            guard.state(),
            &GuardState::YieldedStandby {
                provider: "WireGuard".to_string(),
                since: t_vpn,
            }
        );
        assert_eq!(
            guard.active_conflict_label(&wg).as_deref(),
            Some("WireGuard (yielded)")
        );

        // Switching directly to another full-tunnel VPN updates the standby provider
        // without emitting a redundant teardown or resetting the standby timestamp.
        let t_switch = t_vpn + Duration::from_secs(1);
        let proton = full_tunnel("ProtonVPN", "ProtonVPN", true);
        assert_eq!(guard.evaluate(&proton, t_switch), GuardAction::None);
        assert_eq!(
            guard.state(),
            &GuardState::YieldedStandby {
                provider: "ProtonVPN".to_string(),
                since: t_vpn,
            }
        );
        assert_eq!(
            guard.active_conflict_label(&proton).as_deref(),
            Some("ProtonVPN (yielded)")
        );
    }

    #[test]
    fn three_second_recovery_debounce_resumes_at_exact_boundary() {
        let t0 = Instant::now();
        let mut guard = VpnGuard::new(VpnCoexistence::AutoYield);
        let mullvad = full_tunnel("Mullvad", "wg0-mullvad", true);

        assert_eq!(
            guard.evaluate(&mullvad, t0),
            GuardAction::YieldTun {
                provider: "Mullvad".to_string(),
            }
        );

        // VPN disconnects -> enters Recovering, TUN stays yielded during 3s window.
        let t_clear = t0 + Duration::from_secs(5);
        assert_eq!(guard.evaluate(&VpnScope::None, t_clear), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Recovering { since: t_clear });
        assert!(guard.is_yielded());
        assert_eq!(
            guard.active_conflict_label(&VpnScope::None).as_deref(),
            Some("recovering")
        );

        // Still inside debounce window at 1s and 2999ms.
        assert_eq!(
            guard.evaluate(&VpnScope::None, t_clear + Duration::from_secs(1)),
            GuardAction::None
        );
        assert_eq!(
            guard.evaluate(&VpnScope::None, t_clear + Duration::from_millis(2999)),
            GuardAction::None
        );
        assert_eq!(guard.state(), &GuardState::Recovering { since: t_clear });
        assert!(guard.is_yielded());

        // Exact 3000ms boundary completes recovery and resumes TUN.
        let t_resume = t_clear + Duration::from_secs(3);
        assert_eq!(
            guard.evaluate(&VpnScope::None, t_resume),
            GuardAction::ResumeTun
        );
        assert_eq!(guard.state(), &GuardState::Active);
        assert!(!guard.is_yielded());
        assert_eq!(guard.active_conflict_label(&VpnScope::None), None);

        // Further clear polls stay Active with no action.
        assert_eq!(
            guard.evaluate(&VpnScope::None, t_resume + Duration::from_secs(1)),
            GuardAction::None
        );
        assert_eq!(guard.state(), &GuardState::Active);
    }

    #[test]
    fn flapping_vpn_cancels_recovery_without_resuming_and_restarts_debounce() {
        let t0 = Instant::now();
        let mut guard = VpnGuard::new(VpnCoexistence::AutoYield);
        let nord = full_tunnel("NordVPN", "NordLynx", false);

        assert_eq!(
            guard.evaluate(&nord, t0),
            GuardAction::YieldTun {
                provider: "NordVPN".to_string(),
            }
        );

        // Brief disconnect starts recovery timer at t1.
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(guard.evaluate(&VpnScope::None, t1), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Recovering { since: t1 });

        assert_eq!(
            guard.evaluate(&VpnScope::None, t1 + Duration::from_millis(2500)),
            GuardAction::None
        );

        // VPN reappears before 3s elapses -> cancels recovery smoothly back to YieldedStandby
        // without emitting ResumeTun or a duplicate YieldTun.
        let t2 = t1 + Duration::from_millis(2900);
        assert_eq!(guard.evaluate(&nord, t2), GuardAction::None);
        assert_eq!(
            guard.state(),
            &GuardState::YieldedStandby {
                provider: "NordVPN".to_string(),
                since: t2,
            }
        );
        assert!(guard.is_yielded());

        // Second disconnect starts a fresh 3s debounce window from t3 (not t1).
        let t3 = t2 + Duration::from_secs(1);
        assert_eq!(guard.evaluate(&VpnScope::None, t3), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Recovering { since: t3 });

        assert_eq!(
            guard.evaluate(&VpnScope::None, t3 + Duration::from_millis(2999)),
            GuardAction::None
        );
        assert_eq!(guard.state(), &GuardState::Recovering { since: t3 });

        assert_eq!(
            guard.evaluate(&VpnScope::None, t3 + Duration::from_secs(3)),
            GuardAction::ResumeTun
        );
        assert_eq!(guard.state(), &GuardState::Active);
    }

    #[test]
    fn split_overlay_never_yields_and_allows_recovery_after_exit_node_disables() {
        let t0 = Instant::now();
        let mut guard = VpnGuard::new(VpnCoexistence::AutoYield);
        let tailscale_mesh = split_overlay(&["Tailscale"]);

        // Mesh-only Tailscale never triggers yield or conflict label.
        assert_eq!(guard.evaluate(&tailscale_mesh, t0), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Active);
        assert!(!guard.is_yielded());
        assert_eq!(guard.active_conflict_label(&tailscale_mesh), None);

        // Enabling a Tailscale Exit Node becomes a FullTunnel and yields at 0ms.
        let t1 = t0 + Duration::from_secs(5);
        let tailscale_exit = full_tunnel("Tailscale", "tailscale0", false);
        assert_eq!(
            guard.evaluate(&tailscale_exit, t1),
            GuardAction::YieldTun {
                provider: "Tailscale".to_string(),
            }
        );
        assert_eq!(
            guard.state(),
            &GuardState::YieldedStandby {
                provider: "Tailscale".to_string(),
                since: t1,
            }
        );

        // Disabling the Exit Node drops back to SplitOverlay and starts 3s recovery.
        let t2 = t1 + Duration::from_secs(4);
        assert_eq!(guard.evaluate(&tailscale_mesh, t2), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Recovering { since: t2 });
        assert_eq!(
            guard.active_conflict_label(&tailscale_mesh).as_deref(),
            Some("recovering")
        );

        assert_eq!(
            guard.evaluate(&tailscale_mesh, t2 + Duration::from_secs(3)),
            GuardAction::ResumeTun
        );
        assert_eq!(guard.state(), &GuardState::Active);
        assert_eq!(guard.active_conflict_label(&tailscale_mesh), None);
    }

    #[test]
    fn warn_policy_never_yields_and_reports_conflict_label() {
        let t0 = Instant::now();
        let mut guard = VpnGuard::new(VpnCoexistence::Warn);
        let split = split_overlay(&["Tailscale", "ZeroTier"]);
        let warp = full_tunnel("Cloudflare WARP", "CloudflareWARP", false);

        assert_eq!(guard.evaluate(&VpnScope::None, t0), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Active);
        assert_eq!(guard.active_conflict_label(&VpnScope::None), None);

        assert_eq!(
            guard.evaluate(&split, t0 + Duration::from_secs(1)),
            GuardAction::None
        );
        assert_eq!(guard.state(), &GuardState::Active);
        assert_eq!(guard.active_conflict_label(&split), None);

        assert_eq!(
            guard.evaluate(&warp, t0 + Duration::from_secs(2)),
            GuardAction::WarnOnly {
                provider: "Cloudflare WARP".to_string(),
            }
        );
        assert_eq!(guard.state(), &GuardState::Active);
        assert!(!guard.is_yielded());
        assert_eq!(
            guard.active_conflict_label(&warp).as_deref(),
            Some("Cloudflare WARP (warn)")
        );

        assert_eq!(
            guard.evaluate(&VpnScope::None, t0 + Duration::from_secs(3)),
            GuardAction::None
        );
        assert_eq!(guard.state(), &GuardState::Active);
        assert_eq!(guard.active_conflict_label(&VpnScope::None), None);
    }

    #[test]
    fn off_policy_stays_active_and_suppresses_actions_and_labels() {
        let t0 = Instant::now();
        let mut guard = VpnGuard::new(VpnCoexistence::Off);
        let split = split_overlay(&["Tailscale"]);
        let mullvad = full_tunnel("Mullvad", "Mullvad", true);

        for (idx, scope) in [&VpnScope::None, &split, &mullvad].into_iter().enumerate() {
            let now = t0 + Duration::from_secs(idx as u64);
            assert_eq!(guard.evaluate(scope, now), GuardAction::None);
            assert_eq!(guard.state(), &GuardState::Active);
            assert!(!guard.is_yielded());
            assert_eq!(guard.active_conflict_label(scope), None);
        }
    }

    #[test]
    fn custom_zero_debounce_and_non_monotonic_instant_handling() {
        let t0 = Instant::now();
        let ovpn = full_tunnel("OpenVPN", "tun0", false);

        // Default constructor uses AutoYield + 3s debounce.
        let default_guard = VpnGuard::default();
        assert_eq!(default_guard.policy(), VpnCoexistence::AutoYield);
        assert_eq!(default_guard.recovery_debounce(), DEFAULT_RECOVERY_DEBOUNCE);

        // Custom 500ms debounce plus earlier timestamp safety during Recovering.
        let mut custom =
            VpnGuard::with_recovery_debounce(VpnCoexistence::AutoYield, Duration::from_millis(500));
        assert_eq!(
            custom.evaluate(&ovpn, t0 + Duration::from_secs(1)),
            GuardAction::YieldTun {
                provider: "OpenVPN".to_string(),
            }
        );
        let t_recover = t0 + Duration::from_secs(2);
        assert_eq!(
            custom.evaluate(&VpnScope::None, t_recover),
            GuardAction::None
        );
        // Out-of-order timestamp earlier than `since` must not panic or resume early.
        assert_eq!(custom.evaluate(&VpnScope::None, t0), GuardAction::None);
        assert_eq!(
            custom.evaluate(&VpnScope::None, t_recover + Duration::from_millis(499)),
            GuardAction::None
        );
        assert_eq!(
            custom.evaluate(&VpnScope::None, t_recover + Duration::from_millis(500)),
            GuardAction::ResumeTun
        );
        assert_eq!(custom.state(), &GuardState::Active);

        // Zero debounce resumes immediately once FullTunnel clears.
        let mut instant =
            VpnGuard::with_recovery_debounce(VpnCoexistence::AutoYield, Duration::ZERO);
        assert_eq!(
            instant.evaluate(&ovpn, t0),
            GuardAction::YieldTun {
                provider: "OpenVPN".to_string(),
            }
        );
        assert_eq!(
            instant.evaluate(&VpnScope::None, t0 + Duration::from_millis(1)),
            GuardAction::ResumeTun
        );
        assert_eq!(instant.state(), &GuardState::Active);
    }

    #[test]
    fn optional_yield_confirmation_debounces_flaps_while_preserving_startup_and_kill_switch_zero_ms(
    ) {
        let t0 = Instant::now();
        let wg = full_tunnel("WireGuard", "wg0", false);
        let mullvad_ks = full_tunnel("Mullvad", "Mullvad", true);

        // Startup full-tunnel still yields at 0ms even with yield_confirmation enabled.
        let mut startup_guard = VpnGuard::new(VpnCoexistence::AutoYield)
            .with_yield_confirmation(Duration::from_millis(500));
        assert_eq!(
            startup_guard.yield_confirmation(),
            Duration::from_millis(500)
        );
        assert_eq!(
            startup_guard.evaluate(&wg, t0),
            GuardAction::YieldTun {
                provider: "WireGuard".to_string(),
            }
        );
        assert!(!startup_guard.is_pending_yield());

        // Mid-session: after observing a clear state, transient non-kill-switch flap does not yield.
        let mut guard = VpnGuard::new(VpnCoexistence::AutoYield)
            .with_yield_confirmation(Duration::from_millis(500));
        assert_eq!(guard.evaluate(&VpnScope::None, t0), GuardAction::None);

        let t1 = t0 + Duration::from_secs(5);
        assert_eq!(guard.evaluate(&wg, t1), GuardAction::None);
        assert_eq!(guard.state(), &GuardState::Active);
        assert!(!guard.is_yielded());
        assert!(guard.is_pending_yield());

        // Still inside confirmation window at 499ms.
        assert_eq!(
            guard.evaluate(&wg, t1 + Duration::from_millis(499)),
            GuardAction::None
        );
        assert!(guard.is_pending_yield());

        // Flap clears -> cancels pending confirmation cleanly.
        let t2 = t1 + Duration::from_millis(499);
        assert_eq!(guard.evaluate(&VpnScope::None, t2), GuardAction::None);
        assert!(!guard.is_pending_yield());

        // Sustained mid-session full tunnel confirms at exact 500ms boundary.
        let t3 = t2 + Duration::from_secs(1);
        assert_eq!(guard.evaluate(&wg, t3), GuardAction::None);
        assert_eq!(
            guard.evaluate(&wg, t3 + Duration::from_millis(500)),
            GuardAction::YieldTun {
                provider: "WireGuard".to_string(),
            }
        );
        assert!(guard.is_yielded());
        assert!(!guard.is_pending_yield());

        // Mid-session kill_switch=true still yields immediately at 0ms.
        let mut ks_guard = VpnGuard::new(VpnCoexistence::AutoYield)
            .with_yield_confirmation(Duration::from_millis(500));
        assert_eq!(ks_guard.evaluate(&VpnScope::None, t0), GuardAction::None);
        assert_eq!(
            ks_guard.evaluate(&mullvad_ks, t0 + Duration::from_secs(2)),
            GuardAction::YieldTun {
                provider: "Mullvad".to_string(),
            }
        );
        assert!(ks_guard.is_yielded());
    }

    #[test]
    fn rollback_to_recovering_restarts_debounce_and_preserves_non_autoyield_policies() {
        let t0 = Instant::now();
        let wg = full_tunnel("WireGuard", "wg0", false);
        let mut guard = VpnGuard::new(VpnCoexistence::AutoYield);

        assert_eq!(
            guard.evaluate(&wg, t0),
            GuardAction::YieldTun {
                provider: "WireGuard".to_string(),
            }
        );
        let t_clear = t0 + Duration::from_secs(1);
        assert_eq!(guard.evaluate(&VpnScope::None, t_clear), GuardAction::None);
        let t_resume = t_clear + DEFAULT_RECOVERY_DEBOUNCE;
        assert_eq!(
            guard.evaluate(&VpnScope::None, t_resume),
            GuardAction::ResumeTun
        );
        assert_eq!(guard.state(), &GuardState::Active);

        // If starting TUN failed right after ResumeTun, roll back to Recovering.
        guard.rollback_to_recovering_at(t_resume);
        assert_eq!(guard.state(), &GuardState::Recovering { since: t_resume });
        assert!(guard.is_yielded());
        assert_eq!(
            guard.evaluate(&VpnScope::None, t_resume + Duration::from_millis(2999)),
            GuardAction::None
        );
        assert_eq!(
            guard.evaluate(&VpnScope::None, t_resume + DEFAULT_RECOVERY_DEBOUNCE),
            GuardAction::ResumeTun
        );
        assert_eq!(guard.state(), &GuardState::Active);

        // Smoke-check Instant::now() wrapper too.
        guard.rollback_to_recovering();
        assert!(matches!(guard.state(), GuardState::Recovering { .. }));

        // Off and Warn policies stay Active on rollback.
        let mut off_guard = VpnGuard::new(VpnCoexistence::Off);
        off_guard.rollback_to_recovering_at(t0);
        assert_eq!(off_guard.state(), &GuardState::Active);

        let mut warn_guard = VpnGuard::new(VpnCoexistence::Warn);
        warn_guard.rollback_to_recovering_at(t0);
        assert_eq!(warn_guard.state(), &GuardState::Active);
    }
}
