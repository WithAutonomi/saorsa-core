use lru::LruCache;
use parking_lot::RwLock;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum rate limit keys before evicting oldest (prevents memory DoS from many IPs)
const MAX_RATE_LIMIT_KEYS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub window: Duration,
    pub max_requests: u32,
    pub burst_size: u32,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_update: Instant,
    requests_in_window: u32,
    window_start: Instant,
}

impl Bucket {
    fn new(initial_tokens: f64) -> Self {
        let now = Instant::now();
        Self {
            tokens: initial_tokens,
            last_update: now,
            requests_in_window: 0,
            window_start: now,
        }
    }

    fn try_consume(&mut self, cfg: &EngineConfig) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > cfg.window {
            self.window_start = now;
            self.requests_in_window = 0;
        }
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let refill_rate = cfg.max_requests as f64 / cfg.window.as_secs_f64();
        self.tokens += elapsed * refill_rate;
        self.tokens = self.tokens.min(cfg.burst_size as f64);
        self.last_update = now;
        if self.tokens >= 1.0 && self.requests_in_window < cfg.max_requests {
            self.tokens -= 1.0;
            self.requests_in_window += 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct Engine<K: Eq + Hash + Clone + ToString> {
    cfg: EngineConfig,
    global: Mutex<Bucket>,
    /// LRU cache with max 100k entries to prevent memory DoS from many IPs
    keyed: RwLock<LruCache<K, Bucket>>,
}

impl<K: Eq + Hash + Clone + ToString> Engine<K> {
    pub fn new(cfg: EngineConfig) -> Self {
        let burst_size = cfg.burst_size as f64;
        // Safety: MAX_RATE_LIMIT_KEYS is a const > 0, so unwrap_or with MIN (=1) is safe
        let cache_size = NonZeroUsize::new(MAX_RATE_LIMIT_KEYS).unwrap_or(NonZeroUsize::MIN);
        Self {
            cfg,
            global: Mutex::new(Bucket::new(burst_size)),
            keyed: RwLock::new(LruCache::new(cache_size)),
        }
    }

    pub fn try_consume_global(&self) -> bool {
        match self.global.lock() {
            Ok(mut guard) => guard.try_consume(&self.cfg),
            Err(_poisoned) => {
                // Treat poisoned mutex as a denial to maintain safety
                // and avoid panicking in production code.
                false
            }
        }
    }

    pub fn try_consume_key(&self, key: &K) -> bool {
        let mut map = self.keyed.write();
        // Get or insert with LRU cache (automatically evicts oldest if at capacity)
        if let Some(bucket) = map.get_mut(key) {
            bucket.try_consume(&self.cfg)
        } else {
            let mut bucket = Bucket::new(self.cfg.burst_size as f64);
            let result = bucket.try_consume(&self.cfg);
            map.put(key.clone(), bucket);
            result
        }
    }
}

pub type SharedEngine<K> = Arc<Engine<K>>;
