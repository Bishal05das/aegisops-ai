package inproc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

func testBus(t *testing.T, cfg Config) *Bus {
	t.Helper()
	// Blocking publish by default: a test that silently drops events proves
	// nothing, and the drop-on-full behaviour is exercised explicitly below.
	cfg.BlockOnFull = true
	b := New(cfg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b.Close(ctx)
	})
	return b
}

func event(topic string) ports.Event {
	return ports.Event{
		Type:       topic,
		IncidentID: shared.NewID(),
		ActorType:  "system",
		Payload:    map[string]any{"k": "v"},
	}
}

// waitFor polls until cond holds or the deadline passes. Delivery is
// asynchronous, so a bare assertion after Publish would be a race.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// -----------------------------------------------------------------------------
// Topic matching
// -----------------------------------------------------------------------------

// Pattern semantics must be identical here and on RabbitMQ. A subscription that
// works in tests and silently matches nothing in production would be a
// miserable bug to find, so the AMQP rules are asserted directly.
func TestTopicMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern, key string
		want         bool
	}{
		{"incident.detected", "incident.detected", true},
		{"incident.detected", "incident.resolved", false},

		{"incident.*", "incident.detected", true},
		{"incident.*", "incident.resolved", true},
		{"incident.*", "agent.started", false},
		// '*' is exactly one segment, so it must not span a dot.
		{"incident.*", "incident.detected.extra", false},

		{"#", "anything.at.all", true},
		{"#", "single", true},

		// '#' matches zero or more segments.
		{"incident.#", "incident.detected", true},
		{"incident.#", "incident.detected.extra", true},
		{"incident.#", "incident", true},
		{"incident.#", "agent.started", false},

		{"*.detected", "incident.detected", true},
		{"*.detected", "agent.detected", true},
		{"*.detected", "incident.something.detected", false},

		{"approval.*", "approval.required", true},
		{"tool.*", "tool.requested", true},
		{"tool.*", "incident.detected", false},
	}

	for _, tc := range tests {
		if got := matches(tc.pattern, tc.key); got != tc.want {
			t.Errorf("matches(%q, %q) = %v, want %v", tc.pattern, tc.key, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Delivery
// -----------------------------------------------------------------------------

func TestPublishReachesMatchingSubscribers(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{Workers: 1})
	ctx := context.Background()

	var incidentHits, allHits, agentHits atomic.Int32

	mustSubscribe(ctx, t, b, ports.PatternIncident, func(context.Context, ports.Event) error {
		incidentHits.Add(1)
		return nil
	})
	mustSubscribe(ctx, t, b, ports.PatternAll, func(context.Context, ports.Event) error {
		allHits.Add(1)
		return nil
	})
	mustSubscribe(ctx, t, b, ports.PatternAgent, func(context.Context, ports.Event) error {
		agentHits.Add(1)
		return nil
	})

	if err := b.Publish(ctx, event(ports.TopicIncidentDetected)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if !waitFor(t, time.Second, func() bool {
		return incidentHits.Load() == 1 && allHits.Load() == 1
	}) {
		t.Fatalf("delivery: incident=%d all=%d, want 1 and 1",
			incidentHits.Load(), allHits.Load())
	}
	// The agent subscriber must not have seen an incident event.
	if n := agentHits.Load(); n != 0 {
		t.Errorf("agent.* subscriber received %d incident events", n)
	}
}

// The audit ledger binds to "#" and observes everything without any publisher
// knowing it exists. That is the decoupling the whole architecture rests on.
func TestWildcardSubscriberSeesEverything(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{Workers: 1})
	ctx := context.Background()

	var mu sync.Mutex
	var seen []string

	mustSubscribe(ctx, t, b, ports.PatternAll, func(_ context.Context, e ports.Event) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, e.Type)
		return nil
	})

	topics := []string{
		ports.TopicIncidentDetected, ports.TopicAgentStarted,
		ports.TopicToolRequested, ports.TopicApprovalRequired,
		ports.TopicIncidentResolved,
	}
	for _, topic := range topics {
		if err := b.Publish(ctx, event(topic)); err != nil {
			t.Fatalf("Publish(%s): %v", topic, err)
		}
	}

	if !waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) == len(topics)
	}) {
		mu.Lock()
		t.Fatalf("saw %d of %d events: %v", len(seen), len(topics), seen)
	}
}

func TestPublishWithNoSubscribersIsNotAnError(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{})
	// The orchestrator publishes tool.requested whether or not a harness is
	// listening yet. That must not be an error.
	if err := b.Publish(context.Background(), event(ports.TopicToolRequested)); err != nil {
		t.Errorf("Publish with no subscribers returned %v", err)
	}
}

func TestPublishRejectsUntypedEvent(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{})
	if err := b.Publish(context.Background(), ports.Event{}); err == nil {
		t.Error("an event with no type was accepted; it could never be routed")
	}
}

// The bus fills in what a publisher omitted, so correlation is never silently
// lost between the HTTP request and a subscriber's log lines.
func TestPublishPopulatesMetadata(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{Workers: 1})
	ctx := context.Background()

	got := make(chan ports.Event, 1)
	mustSubscribe(ctx, t, b, ports.PatternAll, func(_ context.Context, e ports.Event) error {
		got <- e
		return nil
	})

	if err := b.Publish(ctx, ports.Event{Type: ports.TopicIncidentDetected}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case e := <-got:
		if e.ID == "" {
			t.Error("event ID was not assigned")
		}
		if e.OccurredAt.IsZero() {
			t.Error("OccurredAt was not assigned")
		}
		if e.Attempt != 1 {
			t.Errorf("Attempt = %d, want 1 on first delivery", e.Attempt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event delivered")
	}
}

// -----------------------------------------------------------------------------
// Retry and dead-lettering
// -----------------------------------------------------------------------------

func TestHandlerFailureIsRetried(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{
		Workers: 1, MaxAttempts: 3, RetryBackoff: time.Millisecond,
	})
	ctx := context.Background()

	var attempts atomic.Int32
	mustSubscribe(ctx, t, b, ports.PatternAll, func(_ context.Context, e ports.Event) error {
		n := attempts.Add(1)
		if n < 3 {
			return errors.New("transient failure")
		}
		// The handler must be able to see which attempt it is on, so it can
		// decide when to give up rather than retrying forever.
		if e.Attempt != int(n) {
			t.Errorf("Attempt = %d on delivery %d", e.Attempt, n)
		}
		return nil
	})

	if err := b.Publish(ctx, event(ports.TopicIncidentDetected)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if !waitFor(t, 2*time.Second, func() bool { return attempts.Load() == 3 }) {
		t.Errorf("attempts = %d, want 3", attempts.Load())
	}
}

func TestExhaustedRetriesAreDeadLettered(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		dead     []ports.Event
		deadErr  error
		attempts atomic.Int32
	)

	b := testBus(t, Config{
		Workers: 1, MaxAttempts: 2, RetryBackoff: time.Millisecond,
		OnDeadLetter: func(e ports.Event, cause error) {
			mu.Lock()
			defer mu.Unlock()
			dead = append(dead, e)
			deadErr = cause
		},
	})
	ctx := context.Background()

	mustSubscribe(ctx, t, b, ports.PatternAll, func(context.Context, ports.Event) error {
		attempts.Add(1)
		return errors.New("permanently broken")
	})

	if err := b.Publish(ctx, event(ports.TopicToolRequested)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if !waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(dead) == 1
	}) {
		t.Fatalf("dead-lettered %d events after %d attempts, want 1", len(dead), attempts.Load())
	}
	if attempts.Load() != 2 {
		t.Errorf("attempts = %d, want MaxAttempts=2", attempts.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if deadErr == nil {
		t.Error("dead-letter callback received no cause")
	}
}

// One broken subscriber must not take down the bus and every other subscription
// with it — the same reasoning as the HTTP recovery middleware.
func TestPanickingHandlerDoesNotKillTheBus(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{Workers: 1, MaxAttempts: 1, RetryBackoff: time.Millisecond})
	ctx := context.Background()

	var healthyHits atomic.Int32

	mustSubscribe(ctx, t, b, ports.PatternAll, func(context.Context, ports.Event) error {
		panic("this subscriber is broken")
	})
	mustSubscribe(ctx, t, b, ports.PatternAll, func(context.Context, ports.Event) error {
		healthyHits.Add(1)
		return nil
	})

	for i := 0; i < 3; i++ {
		if err := b.Publish(ctx, event(ports.TopicIncidentDetected)); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
	}

	if !waitFor(t, 2*time.Second, func() bool { return healthyHits.Load() == 3 }) {
		t.Errorf("the healthy subscriber received %d of 3 events; a panicking "+
			"subscriber affected an unrelated one", healthyHits.Load())
	}
}

// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------

func TestUnsubscribeStopsDelivery(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{Workers: 1})
	ctx := context.Background()

	var hits atomic.Int32
	sub := mustSubscribe(ctx, t, b, ports.PatternAll, func(context.Context, ports.Event) error {
		hits.Add(1)
		return nil
	})

	if err := b.Publish(ctx, event(ports.TopicIncidentDetected)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !waitFor(t, time.Second, func() bool { return hits.Load() == 1 }) {
		t.Fatal("the first event was not delivered")
	}

	unsubCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sub.Unsubscribe(unsubCtx); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	if b.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount = %d after unsubscribing", b.SubscriberCount())
	}

	if err := b.Publish(ctx, event(ports.TopicIncidentDetected)); err != nil {
		t.Fatalf("Publish after unsubscribe: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := hits.Load(); n != 1 {
		t.Errorf("hits = %d after unsubscribing, want 1", n)
	}
}

// An event already accepted has been promised delivery. Dropping it on shutdown
// would lose work the publisher believes is done.
func TestCloseDrainsInFlightEvents(t *testing.T) {
	t.Parallel()

	b := New(Config{Workers: 1, QueueSize: 64, BlockOnFull: true})
	ctx := context.Background()

	var handled atomic.Int32
	if _, err := b.Subscribe(ctx, ports.PatternAll, func(context.Context, ports.Event) error {
		time.Sleep(5 * time.Millisecond) // slow enough to still be draining
		handled.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	const n = 20
	for i := 0; i < n; i++ {
		if err := b.Publish(ctx, event(ports.TopicIncidentDetected)); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
	}

	closeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := b.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := handled.Load(); got != n {
		t.Errorf("handled %d of %d events before closing; the drain lost work", got, n)
	}
}

func TestPublishAfterCloseIsRefused(t *testing.T) {
	t.Parallel()

	b := New(Config{})
	ctx := context.Background()
	if err := b.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := b.Publish(ctx, event(ports.TopicIncidentDetected)); !errors.Is(err, ErrBusClosed) {
		t.Errorf("Publish after Close = %v, want ErrBusClosed", err)
	}
	if _, err := b.Subscribe(ctx, "#", func(context.Context, ports.Event) error { return nil }); !errors.Is(err, ErrBusClosed) {
		t.Errorf("Subscribe after Close = %v, want ErrBusClosed", err)
	}
	// Closing twice must be a no-op, not a panic on a closed channel.
	if err := b.Close(ctx); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}

// Several workers per subscriber is the default, so the concurrent path is the
// one that must be race-free.
func TestConcurrentPublishAndDeliveryIsRaceFree(t *testing.T) {
	t.Parallel()

	b := testBus(t, Config{Workers: 8, QueueSize: 2048})
	ctx := context.Background()

	var handled atomic.Int32
	for i := 0; i < 4; i++ {
		mustSubscribe(ctx, t, b, ports.PatternAll, func(context.Context, ports.Event) error {
			handled.Add(1)
			return nil
		})
	}

	const publishers, each = 8, 25
	var wg sync.WaitGroup
	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := b.Publish(ctx, event(ports.TopicAgentStarted)); err != nil {
					t.Errorf("Publish: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	want := int32(publishers * each * 4) // four subscribers each see every event
	if !waitFor(t, 10*time.Second, func() bool { return handled.Load() == want }) {
		t.Errorf("handled %d deliveries, want %d", handled.Load(), want)
	}
}

func mustSubscribe(ctx context.Context, t *testing.T, b *Bus, pattern string, h ports.EventHandler) ports.Subscription {
	t.Helper()
	sub, err := b.Subscribe(ctx, pattern, h)
	if err != nil {
		t.Fatalf("Subscribe(%s): %v", pattern, err)
	}
	return sub
}
