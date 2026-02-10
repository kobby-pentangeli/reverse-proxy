//! Weighted round-robin load balancer.
//!
//! Distributes requests across healthy upstream backends proportionally
//! to their configured weights. Uses a single [`AtomicUsize`] counter
//! for lock-free, contention-minimized selection.
//!
//! The algorithm expands backends into a virtual slot table at construction
//! time (e.g. a backend with weight 3 occupies three consecutive slots),
//! then selects a slot by incrementing the counter modulo the table length.
//! Unhealthy backends are skipped at selection time, falling through to
//! the next healthy slot.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::upstream::{UpstreamPool, UpstreamState};
use crate::{ProxyError, Result};

/// A weighted round-robin load balancer over an [`UpstreamPool`].
///
/// Selection is lock-free and safe to call concurrently from multiple
/// request handlers. The balancer never modifies backend health state;
/// it only reads it.
#[derive(Debug, Clone)]
pub struct LoadBalancer {
    pool: UpstreamPool,
    /// Pre-expanded slot table mapping counter positions to backend indices.
    slots: Arc<Vec<usize>>,
    /// Monotonic counter incremented on each selection attempt.
    counter: Arc<AtomicUsize>,
}

impl LoadBalancer {
    /// Creates a new round-robin balancer from the given upstream pool.
    ///
    /// Builds a virtual slot table where each backend occupies a number
    /// of consecutive slots equal to its weight. For example, given
    /// backends `[A(w=3), B(w=1)]`, the slot table is `[0, 0, 0, 1]`.
    pub fn new(pool: UpstreamPool) -> Self {
        let slots = pool
            .all()
            .iter()
            .enumerate()
            .flat_map(|(idx, backend)| std::iter::repeat_n(idx, backend.weight() as usize))
            .collect::<Vec<usize>>();

        Self {
            pool,
            slots: Arc::new(slots),
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Selects the next healthy upstream backend.
    ///
    /// Advances the internal counter and walks through the slot table
    /// until a healthy backend is found. If no healthy backend exists
    /// after a full rotation, returns [`ProxyError::NoHealthyUpstream`].
    pub fn next(&self) -> Result<UpstreamState> {
        let slots = self.slots.len();
        if slots == 0 {
            return Err(ProxyError::NoHealthyUpstream);
        }

        let start = self.counter.fetch_add(1, Ordering::Relaxed);
        let backends = self.pool.all();

        (0..slots)
            .map(|offset| {
                let slot_idx = (start + offset) % slots;
                &backends[self.slots[slot_idx]]
            })
            .find(|backend| backend.is_healthy())
            .cloned()
            .ok_or(ProxyError::NoHealthyUpstream)
    }

    /// Returns a reference to the underlying upstream pool.
    pub fn pool(&self) -> &UpstreamPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ValidatedUpstream;

    fn make_pool(specs: &[(&str, u32)]) -> UpstreamPool {
        let validated = specs
            .iter()
            .map(|(addr, weight)| ValidatedUpstream {
                uri: addr.parse().unwrap(),
                weight: *weight,
            })
            .collect::<Vec<ValidatedUpstream>>();
        UpstreamPool::from_validated(&validated)
    }

    #[test]
    fn single_backend_always_selected() {
        let pool = make_pool(&[("http://b1:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        for _ in 0..10 {
            let selected = balancer.next().unwrap();
            assert_eq!(
                selected.uri(),
                &"http://b1:3000".parse::<hyper::Uri>().unwrap()
            );
        }
    }

    #[test]
    fn equal_weight_round_robins() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        let first = balancer.next().unwrap();
        let second = balancer.next().unwrap();
        let third = balancer.next().unwrap();

        assert_ne!(first.uri(), second.uri());
        assert_eq!(first.uri(), third.uri());
    }

    #[test]
    fn weighted_distribution_respects_weights() {
        let pool = make_pool(&[("http://b1:3000", 3), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        let mut b1_count = 0u32;
        let mut b2_count = 0u32;
        let b1_uri = "http://b1:3000".parse::<hyper::Uri>().unwrap();

        for _ in 0..400 {
            let selected = balancer.next().unwrap();
            if *selected.uri() == b1_uri {
                b1_count += 1;
            } else {
                b2_count += 1;
            }
        }

        assert_eq!(b1_count, 300);
        assert_eq!(b2_count, 100);
    }

    #[test]
    fn skips_unhealthy_backends() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        balancer.pool().all()[0].mark_unhealthy();

        for _ in 0..10 {
            let selected = balancer.next().unwrap();
            assert_eq!(
                selected.uri(),
                &"http://b2:3000".parse::<hyper::Uri>().unwrap()
            );
        }
    }

    #[test]
    fn all_unhealthy_returns_error() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        balancer.pool().all()[0].mark_unhealthy();
        balancer.pool().all()[1].mark_unhealthy();

        let result = balancer.next();
        assert!(result.is_err());
    }

    #[test]
    fn recovery_after_mark_healthy() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        balancer.pool().all()[0].mark_unhealthy();
        balancer.pool().all()[1].mark_unhealthy();
        assert!(balancer.next().is_err());

        balancer.pool().all()[0].mark_healthy();
        let selected = balancer.next().unwrap();
        assert_eq!(
            selected.uri(),
            &"http://b1:3000".parse::<hyper::Uri>().unwrap()
        );
    }
}
