//! Rate Limiting and DoS Protection
//!
//! Implements rate limiting for cryptographic operations to prevent
//! brute force attacks and resource exhaustion.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rate limiter for cryptographic operations
#[derive(Clone)]
pub struct RateLimiter {
    /// Operation limits configuration
    limits: HashMap<String, OperationLimit>,
    /// Current counters per client
    counters: HashMap<String, ClientCounter>,
}

/// Limit configuration for an operation type
#[derive(Clone, Debug)]
pub struct OperationLimit {
    /// Maximum operations per second
    pub max_per_second: u32,
    /// Maximum operations per minute
    pub max_per_minute: u32,
    /// Maximum operations per hour
    pub max_per_hour: u32,
    /// Cooldown duration after limit exceeded
    pub cooldown: Duration,
}

impl Default for OperationLimit {
    fn default() -> Self {
        Self {
            max_per_second: 10,
            max_per_minute: 100,
            max_per_hour: 1000,
            cooldown: Duration::from_secs(60),
        }
    }
}

/// Counter for a specific client
#[derive(Clone, Debug)]
struct ClientCounter {
    /// Operations in current second
    second_count: u32,
    /// Operations in current minute
    minute_count: u32,
    /// Operations in current hour
    hour_count: u32,
    /// Last second reset
    last_second: Instant,
    /// Last minute reset
    last_minute: Instant,
    /// Last hour reset
    last_hour: Instant,
    /// Cooldown end time (if any)
    cooldown_until: Option<Instant>,
}

impl Default for ClientCounter {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            second_count: 0,
            minute_count: 0,
            hour_count: 0,
            last_second: now,
            last_minute: now,
            last_hour: now,
            cooldown_until: None,
        }
    }
}

impl RateLimiter {
    /// Create a new rate limiter with default limits
    pub fn new() -> Self {
        let mut limits = HashMap::new();
        
        // Decryption operations (expensive)
        limits.insert("decrypt".to_string(), OperationLimit {
            max_per_second: 5,
            max_per_minute: 50,
            max_per_hour: 500,
            cooldown: Duration::from_secs(120),
        });
        
        // Handshake operations (very expensive)
        limits.insert("handshake".to_string(), OperationLimit {
            max_per_second: 1,
            max_per_minute: 10,
            max_per_hour: 100,
            cooldown: Duration::from_secs(300),
        });
        
        // Encryption operations (cheaper)
        limits.insert("encrypt".to_string(), OperationLimit {
            max_per_second: 20,
            max_per_minute: 200,
            max_per_hour: 2000,
            cooldown: Duration::from_secs(30),
        });
        
        // Key operations (very sensitive)
        limits.insert("key_gen".to_string(), OperationLimit {
            max_per_second: 2,
            max_per_minute: 20,
            max_per_hour: 100,
            cooldown: Duration::from_secs(600),
        });

        Self {
            limits,
            counters: HashMap::new(),
        }
    }

    /// Check if an operation is allowed
    ///
    /// # Arguments
    /// * `operation` - The operation type (decrypt, encrypt, handshake, etc.)
    /// * `client_id` - Unique identifier for the client
    ///
    /// # Returns
    /// `Ok(())` if allowed, `Err(RateLimitError)` if rate limited
    pub fn check(&mut self, operation: &str, client_id: &str) -> Result<(), RateLimitError> {
        let limit = self.limits.get(operation)
            .ok_or_else(|| RateLimitError::UnknownOperation(operation.to_string()))?;
        
        let counter = self.counters.entry(client_id.to_string()).or_default();
        let now = Instant::now();
        
        // Check cooldown
        if let Some(cooldown_end) = counter.cooldown_until {
            if now < cooldown_end {
                let remaining = cooldown_end.duration_since(now);
                return Err(RateLimitError::CooldownActive(remaining));
            }
            counter.cooldown_until = None;
        }
        
        // Update counters
        self.update_counters(counter, limit, now);
        
        // Check limits
        if counter.second_count > limit.max_per_second {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::RateExceeded {
                operation: operation.to_string(),
                limit_type: "per_second".to_string(),
                retry_after: limit.cooldown,
            });
        }
        
        if counter.minute_count > limit.max_per_minute {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::RateExceeded {
                operation: operation.to_string(),
                limit_type: "per_minute".to_string(),
                retry_after: limit.cooldown,
            });
        }
        
        if counter.hour_count > limit.max_per_hour {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::RateExceeded {
                operation: operation.to_string(),
                limit_type: "per_hour".to_string(),
                retry_after: limit.cooldown,
            });
        }
        
        // Increment counters
        counter.second_count += 1;
        counter.minute_count += 1;
        counter.hour_count += 1;
        
        Ok(())
    }

    /// Update counters based on time elapsed
    fn update_counters(&self, counter: &mut ClientCounter, limit: &OperationLimit, now: Instant) {
        // Reset second counter
        if now.duration_since(counter.last_second) >= Duration::from_secs(1) {
            counter.second_count = 0;
            counter.last_second = now;
        }
        
        // Reset minute counter
        if now.duration_since(counter.last_minute) >= Duration::from_secs(60) {
            counter.minute_count = 0;
            counter.last_minute = now;
        }
        
        // Reset hour counter
        if now.duration_since(counter.last_hour) >= Duration::from_secs(3600) {
            counter.hour_count = 0;
            counter.last_hour = now;
        }
    }

    /// Reset all counters for a client
    pub fn reset(&mut self, client_id: &str) {
        self.counters.remove(client_id);
    }

    /// Add a custom operation limit
    pub fn add_limit(&mut self, operation: String, limit: OperationLimit) {
        self.limits.insert(operation, limit);
    }

    /// Get remaining quota for an operation
    pub fn remaining(&self, operation: &str, client_id: &str) -> Option<RemainingQuota> {
        let limit = self.limits.get(operation)?;
        let counter = self.counters.get(client_id)?;
        
        Some(RemainingQuota {
            per_second: limit.max_per_second.saturating_sub(counter.second_count),
            per_minute: limit.max_per_minute.saturating_sub(counter.minute_count),
            per_hour: limit.max_per_hour.saturating_sub(counter.hour_count),
        })
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Remaining quota information
#[derive(Clone, Debug)]
pub struct RemainingQuota {
    /// Remaining operations this second
    pub per_second: u32,
    /// Remaining operations this minute
    pub per_minute: u32,
    /// Remaining operations this hour
    pub per_hour: u32,
}

/// Rate limit error
#[derive(Clone, Debug)]
pub enum RateLimitError {
    /// Rate limit exceeded
    RateExceeded {
        operation: String,
        limit_type: String,
        retry_after: Duration,
    },
    /// Client is in cooldown period
    CooldownActive(Duration),
    /// Unknown operation type
    UnknownOperation(String),
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateExceeded { operation, limit_type, retry_after } => {
                write!(f, "Rate limit exceeded for {} ({}). Retry after {:?}s", 
                       operation, limit_type, retry_after.as_secs())
            }
            Self::CooldownActive(remaining) => {
                write!(f, "Cooldown active. Retry after {:?}s", remaining.as_secs())
            }
            Self::UnknownOperation(op) => {
                write!(f, "Unknown operation: {}", op)
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let mut limiter = RateLimiter::new();
        
        // Should allow first request
        assert!(limiter.check("decrypt", "client1").is_ok());
    }

    #[test]
    fn test_rate_limiter_limit() {
        let mut limiter = RateLimiter::new();
        
        // Exhaust per-second limit (5 for decrypt)
        for _ in 0..5 {
            assert!(limiter.check("decrypt", "client1").is_ok());
        }
        
        // Should now be limited
        assert!(limiter.check("decrypt", "client1").is_err());
    }

    #[test]
    fn test_rate_limiter_different_clients() {
        let mut limiter = RateLimiter::new();
        
        // Exhaust limit for client1
        for _ in 0..5 {
            limiter.check("decrypt", "client1").unwrap();
        }
        
        // client1 should be limited
        assert!(limiter.check("decrypt", "client1").is_err());
        
        // client2 should still be allowed
        assert!(limiter.check("decrypt", "client2").is_ok());
    }

    #[test]
    fn test_remaining_quota() {
        let mut limiter = RateLimiter::new();
        
        limiter.check("decrypt", "client1").unwrap();
        
        let remaining = limiter.remaining("decrypt", "client1").unwrap();
        assert_eq!(remaining.per_second, 4);
    }
}
