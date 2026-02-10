//! Per-backend health state tracking.
//!
//! Each upstream backend is represented by an [`UpstreamState`] that holds
//! its validated URI, weight, and atomic health counters. Health transitions
//! are lock-free: consecutive failures are tracked via [`AtomicU32`] and
//! the healthy/unhealthy flag via [`AtomicBool`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::config::ValidatedUpstream;

/// Manages the full set of upstream backends and their health states.
#[derive(Debug, Clone)]
pub struct UpstreamPool {
    backends: Arc<Vec<UpstreamState>>,
}

/// Runtime state for a single upstream backend.
#[derive(Debug, Clone)]
pub struct UpstreamState {
    state: Arc<InnerState>,
}

#[derive(Debug)]
struct InnerState {
    /// The validated upstream URI.
    uri: hyper::Uri,
    /// Relative weight for load balancing.
    weight: u32,
    /// Number of consecutive failures observed.
    consecutive_failures: AtomicU32,
    /// Whether this backend is currently considered healthy.
    healthy: AtomicBool,
}

impl UpstreamPool {
    /// Constructs a pool from validated upstream configurations, marking
    /// all backends as initially healthy.
    pub fn from_validated(upstreams: &[ValidatedUpstream]) -> Self {
        let backends = upstreams.iter().map(UpstreamState::new).collect();
        Self {
            backends: Arc::new(backends),
        }
    }

    /// Returns a slice of all backends (healthy and unhealthy).
    pub fn all(&self) -> &[UpstreamState] {
        &self.backends
    }

    /// Returns the backends that are currently marked healthy.
    pub fn healthy(&self) -> Vec<&UpstreamState> {
        self.backends.iter().filter(|b| b.is_healthy()).collect()
    }

    /// Returns the total number of configured backends.
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// Returns `true` if no backends are configured.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }
}

impl UpstreamState {
    /// Creates a new healthy upstream from a validated configuration entry.
    pub fn new(backend: &ValidatedUpstream) -> Self {
        Self {
            state: Arc::new(InnerState {
                uri: backend.uri.clone(),
                weight: backend.weight,
                consecutive_failures: AtomicU32::new(0),
                healthy: AtomicBool::new(true),
            }),
        }
    }

    /// Returns the upstream URI.
    pub fn uri(&self) -> &hyper::Uri {
        &self.state.uri
    }

    /// Returns the load-balancing weight.
    pub fn weight(&self) -> u32 {
        self.state.weight
    }

    /// Returns `true` if this backend is currently healthy.
    pub fn is_healthy(&self) -> bool {
        self.state.healthy.load(Ordering::Acquire)
    }

    /// Records a successful request, resetting the failure counter and
    /// marking the backend healthy.
    pub fn record_success(&self) {
        self.state.consecutive_failures.store(0, Ordering::Release);
        self.state.healthy.store(true, Ordering::Release);
    }

    /// Records a failed request, incrementing the consecutive failure counter.
    /// If the counter reaches `threshold`, the backend is marked unhealthy.
    ///
    /// Returns `true` if this failure caused a health transition from
    /// healthy to unhealthy.
    pub fn record_failure(&self, threshold: u32) -> bool {
        let prev = self
            .state
            .consecutive_failures
            .fetch_add(1, Ordering::AcqRel);
        let new_count = prev.saturating_add(1);

        if new_count >= threshold && self.state.healthy.swap(false, Ordering::AcqRel) {
            return true;
        }

        false
    }

    /// Marks this backend as healthy, resetting the failure counter.
    pub fn mark_healthy(&self) {
        self.state.consecutive_failures.store(0, Ordering::Release);
        self.state.healthy.store(true, Ordering::Release);
    }

    /// Marks this backend as unhealthy.
    pub fn mark_unhealthy(&self) {
        self.state.healthy.store(false, Ordering::Release);
    }

    /// Returns the current consecutive failure count.
    pub fn failure_count(&self) -> u32 {
        self.state.consecutive_failures.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_upstream(addr: &str, weight: u32) -> ValidatedUpstream {
        ValidatedUpstream {
            uri: addr.parse().unwrap(),
            weight,
        }
    }

    #[test]
    fn new_upstream_starts_healthy() {
        let state = UpstreamState::new(&test_upstream("http://localhost:3000", 1));
        assert!(state.is_healthy());
        assert_eq!(state.failure_count(), 0);
    }

    #[test]
    fn record_success_resets_failures() {
        let state = UpstreamState::new(&test_upstream("http://localhost:3000", 1));
        state.record_failure(5);
        state.record_failure(5);
        assert_eq!(state.failure_count(), 2);

        state.record_success();
        assert_eq!(state.failure_count(), 0);
        assert!(state.is_healthy());
    }

    #[test]
    fn record_failure_marks_unhealthy_at_threshold() {
        let state = UpstreamState::new(&test_upstream("http://localhost:3000", 1));

        assert!(!state.record_failure(3));
        assert!(!state.record_failure(3));
        assert!(state.record_failure(3));

        assert!(!state.is_healthy());
    }

    #[test]
    fn record_failure_beyond_threshold_does_not_retrigger() {
        let state = UpstreamState::new(&test_upstream("http://localhost:3000", 1));

        state.record_failure(2);
        assert!(state.record_failure(2));
        assert!(!state.record_failure(2));
    }

    #[test]
    fn pool_healthy_filters_unhealthy_backends() {
        let backends = vec![
            test_upstream("http://b1:3000", 1),
            test_upstream("http://b2:3000", 1),
            test_upstream("http://b3:3000", 1),
        ];
        let pool = UpstreamPool::from_validated(&backends);

        pool.all()[1].mark_unhealthy();

        let healthy = pool.healthy();
        assert_eq!(healthy.len(), 2);
        assert_eq!(
            healthy[0].uri(),
            &"http://b1:3000".parse::<hyper::Uri>().unwrap()
        );
        assert_eq!(
            healthy[1].uri(),
            &"http://b3:3000".parse::<hyper::Uri>().unwrap()
        );
    }
}
