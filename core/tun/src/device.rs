use std::sync::{Arc, Mutex, PoisonError};

/// Bounded, lazily-grown slab pool for reusable packet `Vec<u8>` buffers.
///
/// Starts with zero pre-allocated slabs and retains at most `max_pooled` buffers
/// for reuse across TUN read/write hot paths.
#[derive(Debug, Clone)]
pub struct PacketPool {
    slabs: Arc<Mutex<Vec<Vec<u8>>>>,
    slab_cap: usize,
    max_pooled: usize,
}

impl PacketPool {
    /// Creates a new bounded packet buffer pool with zero upfront allocation.
    pub fn new(slab_cap: usize, max_pooled: usize) -> Self {
        Self {
            slabs: Arc::new(Mutex::new(Vec::new())),
            slab_cap,
            max_pooled,
        }
    }

    /// Returns a cleared buffer with at least `slab_cap` capacity, reusing a pooled
    /// slab when available or allocating lazily otherwise.
    pub fn take(&self) -> Vec<u8> {
        let pooled = {
            let mut guard = self.slabs.lock().unwrap_or_else(PoisonError::into_inner);
            guard.pop()
        };
        match pooled {
            Some(mut buf) => {
                buf.clear();
                if buf.capacity() < self.slab_cap {
                    buf.reserve_exact(self.slab_cap);
                }
                buf
            }
            None => Vec::with_capacity(self.slab_cap),
        }
    }

    /// Clears and returns `buf` to the pool if the pool has not reached `max_pooled`
    /// and the buffer capacity is within `[slab_cap, 2 * slab_cap]`.
    pub fn put(&self, mut buf: Vec<u8>) {
        if self.max_pooled == 0 {
            return;
        }
        buf.clear();
        let max_retained_cap = self.slab_cap.saturating_mul(2);
        if buf.capacity() < self.slab_cap || buf.capacity() > max_retained_cap {
            return;
        }
        let mut guard = self.slabs.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.len() < self.max_pooled {
            guard.push(buf);
        } else {
            drop(guard);
            drop(buf);
        }
    }

    /// Configured minimum capacity for slabs returned by [`Self::take`].
    pub fn slab_cap(&self) -> usize {
        self.slab_cap
    }

    /// Maximum number of buffers retained in the pool.
    pub fn max_pooled(&self) -> usize {
        self.max_pooled
    }

    /// Number of buffers currently cached in the pool.
    pub fn pooled_len(&self) -> usize {
        self.slabs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_prealloc_and_lazy_growth() {
        let pool = PacketPool::new(2048, 4);
        assert_eq!(pool.slab_cap(), 2048);
        assert_eq!(pool.max_pooled(), 4);
        assert_eq!(pool.pooled_len(), 0);
        assert_eq!(pool.slabs.lock().unwrap().capacity(), 0);

        let buf = pool.take();
        assert!(buf.is_empty());
        assert!(buf.capacity() >= 2048);
        assert_eq!(pool.pooled_len(), 0);
    }

    #[test]
    fn reuses_pooled_slab_and_clears_contents() {
        let pool = PacketPool::new(1500, 4);
        let mut buf = pool.take();
        buf.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
        let ptr = buf.as_ptr();

        pool.put(buf);
        assert_eq!(pool.pooled_len(), 1);

        let reused = pool.take();
        assert!(reused.is_empty());
        assert!(reused.capacity() >= 1500);
        assert_eq!(reused.as_ptr(), ptr);
        assert_eq!(pool.pooled_len(), 0);
    }

    #[test]
    fn enforces_max_pooled_cap() {
        let pool = PacketPool::new(1500, 3);
        let bufs: Vec<Vec<u8>> = (0..5).map(|_| pool.take()).collect();
        for buf in bufs {
            pool.put(buf);
        }
        assert_eq!(pool.pooled_len(), 3);

        let zero_pool = PacketPool::new(1500, 0);
        let buf = zero_pool.take();
        zero_pool.put(buf);
        assert_eq!(zero_pool.pooled_len(), 0);
    }

    #[test]
    fn clone_shares_underlying_pool() {
        let pool_a = PacketPool::new(1500, 2);
        let pool_b = pool_a.clone();

        let mut buf = pool_a.take();
        buf.push(0x45);
        let ptr = buf.as_ptr();
        pool_a.put(buf);

        let taken = pool_b.take();
        assert!(taken.is_empty());
        assert_eq!(taken.as_ptr(), ptr);
        assert_eq!(pool_a.pooled_len(), 0);
    }

    #[test]
    fn drops_excessively_oversized_buffers() {
        let pool = PacketPool::new(1500, 2);
        // Reject oversized buffers (> 2 * slab_cap = 3000) and undersized buffers (< slab_cap).
        pool.put(Vec::with_capacity(64 * 1024));
        pool.put(Vec::with_capacity(3001));
        pool.put(Vec::with_capacity(512));
        assert_eq!(pool.pooled_len(), 0);

        // Retain buffers within [slab_cap, 2 * slab_cap].
        pool.put(Vec::with_capacity(3000));
        assert_eq!(pool.pooled_len(), 1);
    }
}
