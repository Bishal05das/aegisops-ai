// Package inproc implements the event bus with channels and goroutines.
//
// Not a stub. It is the bus for single-node development and for every test that
// exercises orchestration, and it implements the semantics that matter — topic
// matching, per-subscriber queues, bounded retry, dead-lettering and graceful
// drain — so that code written against it behaves the same on RabbitMQ.
//
// The one semantic it cannot offer is durability: events live in memory and a
// crash loses whatever was in flight. That is acceptable here because Postgres
// is the system of record ([ADR 0004](../../../docs/adr/0004-rabbitmq-over-kafka.md));
// the bus moves facts, it does not hold them.
package inproc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/pkg/id"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Config configures the bus.
type Config struct {
	// QueueSize bounds each subscriber's buffer.
	//
	// Bounded on purpose. An unbounded queue turns a slow subscriber into
	// unbounded memory growth, and the process dies of something that looks
	// nothing like the original slowness. A bounded queue surfaces the problem
	// as backpressure, where it can be seen.
	QueueSize int

	// Workers is the number of concurrent handler goroutines per subscriber.
	//
	// More than one means events for a subscriber may be handled out of order.
	// That is the right default here — handlers are idempotent and ordering is
	// carried by incident_events.seq, not by delivery order — but a subscriber
	// needing strict order must use one worker.
	Workers int

	// MaxAttempts bounds redelivery before an event is dead-lettered.
	MaxAttempts int

	// RetryBackoff is the delay before redelivering a failed event.
	RetryBackoff time.Duration

	// BlockOnFull decides what happens when a subscriber's queue is full.
	//
	// False (the default) drops the event and logs loudly: one slow subscriber
	// must not stall the publisher and, through it, an incident's whole
	// investigation. True applies real backpressure, which suits a test that
	// must not lose events.
	BlockOnFull bool

	// OnDeadLetter receives events that exhausted their attempts. Without a
	// handler they are logged and discarded.
	OnDeadLetter func(e ports.Event, cause error)

	Logger *slog.Logger
}

// Defaults applied to zero-valued config fields.
const (
	DefaultQueueSize    = 256
	DefaultWorkers      = 4
	DefaultMaxAttempts  = 3
	DefaultRetryBackoff = 100 * time.Millisecond
)

// Bus is an in-process implementation of ports.EventBus.
type Bus struct {
	cfg Config
	log *slog.Logger

	mu     sync.RWMutex
	subs   []*subscription
	closed bool

	// wg tracks subscriber goroutines so Close can wait for them.
	wg sync.WaitGroup
}

// New builds an in-process bus.
func New(cfg Config) *Bus {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = DefaultRetryBackoff
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Bus{cfg: cfg, log: cfg.Logger}
}

var _ ports.EventBus = (*Bus)(nil)

// ErrBusClosed is returned by Publish and Subscribe after Close.
var ErrBusClosed = errors.New("inproc: the event bus is closed")

// Publish delivers an event to every matching subscriber.
//
// Returns once the event is queued, not once it is handled. Publishing is
// therefore fast and non-blocking, which matters: an incident's progress must
// not be gated on how quickly the slowest subscriber works.
func (b *Bus) Publish(ctx context.Context, e ports.Event) error {
	const op = "inproc.Bus.Publish"

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("%s: %w", op, ErrBusClosed)
	}
	if e.Type == "" {
		return fmt.Errorf("%s: event has no type", op)
	}

	// Fill in what the publisher did not, so every subscriber sees a complete
	// event and correlation is never silently lost.
	if e.ID == "" {
		e.ID = id.New()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if e.RequestID == "" {
		e.RequestID = logger.RequestID(ctx)
	}
	if e.TraceID == "" {
		e.TraceID = logger.TraceID(ctx)
	}
	e.Attempt = 1

	delivered := 0
	for _, sub := range b.subs {
		if !matches(sub.pattern, e.Type) {
			continue
		}
		delivered++
		if err := sub.enqueue(e, b.cfg.BlockOnFull); err != nil {
			// A dropped event is a real loss, so it is logged at warn with
			// everything needed to understand what went missing.
			b.log.Warn("dropped an event: the subscriber queue is full",
				"topic", e.Type, "pattern", sub.pattern,
				"incident_id", e.IncidentID.String(),
				"queue_size", b.cfg.QueueSize)
		}
	}

	// Not an error. An event with no listener is normal — the orchestrator
	// publishes tool.requested whether or not a harness is wired in yet — but
	// it is worth seeing at debug when tracing why something did not happen.
	if delivered == 0 {
		b.log.Debug("published an event with no subscribers", "topic", e.Type)
	}
	return nil
}

// Subscribe registers a handler for a topic pattern.
func (b *Bus) Subscribe(ctx context.Context, pattern string, h ports.EventHandler) (ports.Subscription, error) {
	const op = "inproc.Bus.Subscribe"

	if pattern == "" {
		return nil, fmt.Errorf("%s: pattern is required", op)
	}
	if h == nil {
		return nil, fmt.Errorf("%s: handler is required", op)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, fmt.Errorf("%s: %w", op, ErrBusClosed)
	}

	sub := &subscription{
		bus:     b,
		pattern: pattern,
		handler: h,
		queue:   make(chan ports.Event, b.cfg.QueueSize),
		done:    make(chan struct{}),
		log:     b.log.With("subscription", pattern),
	}
	b.subs = append(b.subs, sub)

	for i := 0; i < b.cfg.Workers; i++ {
		b.wg.Add(1)
		sub.workers.Add(1)
		go func() {
			defer b.wg.Done()
			defer sub.workers.Done()
			sub.work(ctx)
		}()
	}
	// One goroutine owns closing `done`, so Unsubscribe has a single signal to
	// wait on regardless of the worker count.
	go func() {
		sub.workers.Wait()
		close(sub.done)
	}()

	b.log.Debug("subscribed", "pattern", pattern, "workers", b.cfg.Workers)
	return sub, nil
}

// Close stops the bus and waits for in-flight handlers.
//
// Draining rather than severing: an event already accepted has been promised
// delivery, and dropping it on shutdown would lose work the publisher believes
// is done. The ctx bounds how long that promise is honoured.
func (b *Bus) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	subs := b.subs
	b.subs = nil
	b.mu.Unlock()

	for _, sub := range subs {
		sub.closeQueue()
	}

	drained := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(drained)
	}()

	select {
	case <-drained:
		b.log.Debug("event bus drained cleanly")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("inproc.Bus.Close: handlers did not drain: %w", ctx.Err())
	}
}

// SubscriberCount reports the number of live subscriptions, for tests and for a
// metrics gauge.
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// subscription is one registered handler and its queue.
type subscription struct {
	bus     *Bus
	pattern string
	handler ports.EventHandler
	queue   chan ports.Event
	log     *slog.Logger

	closeOnce sync.Once
	// workers tracks this subscription's goroutines so `done` closes exactly
	// once, after the last one exits. Having each worker try to close it — the
	// obvious approach — races: several can pass the same guard and one panics
	// on a double close.
	workers sync.WaitGroup
	done    chan struct{}
}

// Topic implements ports.Subscription.
func (s *subscription) Topic() string { return s.pattern }

// Unsubscribe implements ports.Subscription.
func (s *subscription) Unsubscribe(ctx context.Context) error {
	s.bus.mu.Lock()
	for i, other := range s.bus.subs {
		if other == s {
			s.bus.subs = append(s.bus.subs[:i], s.bus.subs[i+1:]...)
			break
		}
	}
	s.bus.mu.Unlock()

	s.closeQueue()

	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *subscription) closeQueue() {
	s.closeOnce.Do(func() { close(s.queue) })
}

// enqueue adds an event to the subscriber's queue.
func (s *subscription) enqueue(e ports.Event, block bool) error {
	if block {
		s.queue <- e
		return nil
	}
	select {
	case s.queue <- e:
		return nil
	default:
		return errors.New("queue is full")
	}
}

// work consumes the queue until it closes.
func (s *subscription) work(ctx context.Context) {
	for e := range s.queue {
		s.deliver(ctx, e)
	}
}

// deliver invokes the handler, retrying on failure up to MaxAttempts.
func (s *subscription) deliver(ctx context.Context, e ports.Event) {
	cfg := s.bus.cfg

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		e.Attempt = attempt

		// Correlation is restored onto the handler's context, so a log line
		// emitted deep inside a subscriber still ties back to the HTTP request
		// that started the investigation.
		hctx := ctx
		if e.RequestID != "" {
			hctx = logger.WithRequestID(hctx, e.RequestID)
		}
		if e.TraceID != "" {
			hctx = logger.WithTraceID(hctx, e.TraceID)
		}
		if !e.IncidentID.IsZero() {
			hctx = logger.WithIncidentID(hctx, e.IncidentID.String())
		}

		err := s.safeHandle(hctx, e)
		if err == nil {
			return
		}

		if attempt == cfg.MaxAttempts {
			s.log.Error("event handler failed after every attempt; dead-lettering",
				"topic", e.Type, "attempts", attempt,
				"incident_id", e.IncidentID.String(), "error", err)
			if cfg.OnDeadLetter != nil {
				cfg.OnDeadLetter(e, err)
			}
			return
		}

		s.log.Warn("event handler failed; retrying",
			"topic", e.Type, "attempt", attempt, "error", err)

		select {
		case <-time.After(cfg.RetryBackoff * time.Duration(attempt)):
		case <-ctx.Done():
			return
		}
	}
}

// safeHandle runs the handler, converting a panic into an error.
//
// A panicking subscriber must not take down the bus and every other
// subscription with it. This is the same reasoning as the HTTP recovery
// middleware: one broken handler is a failed event, not a failed process.
func (s *subscription) safeHandle(ctx context.Context, e ports.Event) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("handler panicked: %v", p)
			s.log.Error("event handler panicked",
				"topic", e.Type, "panic", fmt.Sprint(p),
				"incident_id", e.IncidentID.String())
		}
	}()
	return s.handler(ctx, e)
}

// matches reports whether an AMQP-style topic pattern matches a routing key.
//
// Implemented here rather than deferred to the broker so that the in-process bus
// and RabbitMQ agree on what a pattern means. A subscription that works in tests
// and silently matches nothing in production would be a miserable bug to find.
//
//   - matches exactly one segment
//     #  matches zero or more segments
func matches(pattern, key string) bool {
	if pattern == "#" {
		return true
	}
	if pattern == key {
		return true
	}
	return matchSegments(strings.Split(pattern, "."), strings.Split(key, "."))
}

// matchSegments walks pattern and key segments, recursing at '#'.
func matchSegments(pattern, key []string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case "#":
			// '#' matches zero or more segments, so try every split point.
			// Zero-length match first, which terminates a trailing '#'.
			if len(pattern) == 1 {
				return true
			}
			for i := 0; i <= len(key); i++ {
				if matchSegments(pattern[1:], key[i:]) {
					return true
				}
			}
			return false
		case "*":
			if len(key) == 0 {
				return false
			}
		default:
			if len(key) == 0 || pattern[0] != key[0] {
				return false
			}
		}
		pattern, key = pattern[1:], key[1:]
	}
	return len(key) == 0
}
