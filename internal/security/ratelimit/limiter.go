// Package ratelimit implements a token-bucket limiter keyed by principal.
//
// Token bucket rather than a fixed window, because a fixed window lets a caller
// spend its whole quota at 59.9s and again at 60.1s — twice the intended rate
// across the boundary. A bucket refills continuously, so the burst is bounded by
// the bucket size and the sustained rate is exactly the refill rate.
//
// Refill is computed lazily from elapsed time rather than by a background
// ticker. One goroutine per bucket would be thousands of goroutines under load;
// one shared ticker would still have to walk every bucket. Deriving the level on
// read costs a subtraction and needs no scheduler involvement at all.
package ratelimit

import (
	"sync"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// Decision is the outcome of a rate-limit check.
type Decision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Remaining is the whole tokens left after this request.
	Remaining int
	// Limit is the configured burst size.
	Limit int
	// RetryAfter is how long until one token is available. Zero when allowed.
	//
	// This is why the limiter returns a struct rather than a bool: a 429 with
	// no Retry-After tells a client to guess, and clients guess badly — usually
	// by retrying immediately, which is the opposite of what the limit wants.
	RetryAfter time.Duration
	// ResetAt is when the bucket will be full again.
	ResetAt time.Time
}

// Config configures a Limiter.
type Config struct {
	// Rate is the sustained refill, in tokens per second.
	Rate float64
	// Burst is the bucket size — the most that can be spent at once.
	Burst int
	// TTL is how long an idle bucket is retained before eviction.
	TTL time.Duration
	// Clock is injectable so tests can advance time without sleeping.
	Clock shared.Clock
}

// Defaults applied when a field is zero.
const (
	DefaultRate  = 20
	DefaultBurst = 40
	DefaultTTL   = 10 * time.Minute
)

// bucket is one principal's token bucket.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter is a keyed token-bucket rate limiter.
//
// Safe for concurrent use. A single mutex guards the map: the critical section
// is a map lookup and a few arithmetic operations, so sharding would add
// complexity well before it added throughput. If profiling ever shows contention
// here, shard by key hash rather than reaching for sync.Map — which optimises
// for read-mostly workloads, and every operation here is a write.
type Limiter struct {
	rate  float64
	burst int
	ttl   time.Duration
	clock shared.Clock

	mu      sync.Mutex
	buckets map[string]*bucket
	// lastSweep bounds how often eviction walks the map.
	lastSweep time.Time
}

// New builds a limiter.
func New(cfg Config) *Limiter {
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.Clock == nil {
		cfg.Clock = shared.SystemClock{}
	}
	return &Limiter{
		rate:      cfg.Rate,
		burst:     cfg.Burst,
		ttl:       cfg.TTL,
		clock:     cfg.Clock,
		buckets:   make(map[string]*bucket),
		lastSweep: cfg.Clock.Now(),
	}
}

// sweepInterval bounds how often Allow walks the map to evict idle buckets.
//
// Eviction is not optional. Keying by IP means an attacker can mint a new key
// per request from a botnet, and a map that only grows is a memory-exhaustion
// vector — the limiter becoming the outage it exists to prevent.
const sweepInterval = time.Minute

// Allow consumes one token for key and reports the decision.
func (l *Limiter) Allow(key string) Decision {
	return l.AllowN(key, 1)
}

// AllowN consumes n tokens for key.
//
// Costing an operation more than one token is how an expensive endpoint can be
// limited more tightly than a cheap one without a second limiter: an LLM
// completion is worth more than a health check.
func (l *Limiter) AllowN(key string, n int) Decision {
	now := l.clock.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) >= sweepInterval {
		l.evictLocked(now)
		l.lastSweep = now
	}

	b, exists := l.buckets[key]
	if !exists {
		// A new principal starts full, so a first request is never refused.
		b = &bucket{tokens: float64(l.burst), lastSeen: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		if elapsed > 0 {
			b.tokens = minFloat(float64(l.burst), b.tokens+elapsed*l.rate)
		}
	}
	b.lastSeen = now

	cost := float64(n)
	if b.tokens < cost {
		// Refuse without deducting. Charging for a refused request would let a
		// caller hammering the endpoint hold their own bucket permanently empty
		// and never recover — punishing a misbehaving client is not the job, and
		// it makes the retry advice below a lie.
		deficit := cost - b.tokens
		retryAfter := time.Duration(deficit / l.rate * float64(time.Second))
		return Decision{
			Allowed:    false,
			Remaining:  int(b.tokens),
			Limit:      l.burst,
			RetryAfter: retryAfter,
			ResetAt:    now.Add(l.fullRefillDuration(b.tokens)),
		}
	}

	b.tokens -= cost
	return Decision{
		Allowed:   true,
		Remaining: int(b.tokens),
		Limit:     l.burst,
		ResetAt:   now.Add(l.fullRefillDuration(b.tokens)),
	}
}

// Peek reports whether a request would be allowed, without consuming anything.
//
// This exists because AllowN(key, 0) does not do it: with a cost of zero the
// `tokens < cost` test is `tokens < 0`, which is false even for an empty bucket,
// so a zero-cost call always reports Allowed. That looks like a peek and is not
// one — it is a check that can never fail.
//
// Login uses this to refuse an attempt *before* verifying a password, so an
// exhausted budget costs no argon2 work, and then charges the bucket only when
// the attempt actually fails. A correct login is never charged, so a user who
// mistypes twice is not throttled on their third, successful try.
func (l *Limiter) Peek(key string) Decision {
	now := l.clock.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, exists := l.buckets[key]
	if !exists {
		// An unseen principal has a full bucket.
		return Decision{Allowed: true, Remaining: l.burst, Limit: l.burst}
	}

	// Project the refill without writing it back, so a peek leaves no trace.
	tokens := b.tokens
	if elapsed := now.Sub(b.lastSeen).Seconds(); elapsed > 0 {
		tokens = minFloat(float64(l.burst), tokens+elapsed*l.rate)
	}

	if tokens < 1 {
		deficit := 1 - tokens
		return Decision{
			Allowed:    false,
			Remaining:  0,
			Limit:      l.burst,
			RetryAfter: time.Duration(deficit / l.rate * float64(time.Second)),
			ResetAt:    now.Add(l.fullRefillDuration(tokens)),
		}
	}
	return Decision{
		Allowed:   true,
		Remaining: int(tokens),
		Limit:     l.burst,
		ResetAt:   now.Add(l.fullRefillDuration(tokens)),
	}
}

// Reset drops a principal's bucket, restoring a full allowance.
//
// Used after a successful login: the failed-attempt budget that throttled the
// guessing should not then throttle the legitimate session that follows.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// Len reports the number of tracked principals, for a metrics gauge and for
// tests asserting that eviction actually runs.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// evictLocked removes buckets untouched for longer than the TTL.
//
// A bucket idle past its TTL has necessarily refilled — the TTL exceeds a full
// refill for any sane configuration — so dropping it loses no state a caller
// could observe. It is indistinguishable from a fresh full bucket.
func (l *Limiter) evictLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.ttl {
			delete(l.buckets, key)
		}
	}
}

// fullRefillDuration is how long until a bucket at the given level is full.
func (l *Limiter) fullRefillDuration(tokens float64) time.Duration {
	missing := float64(l.burst) - tokens
	if missing <= 0 {
		return 0
	}
	return time.Duration(missing / l.rate * float64(time.Second))
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
