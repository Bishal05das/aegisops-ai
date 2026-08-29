package id

import (
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewFormat(t *testing.T) {
	t.Parallel()

	s := New()
	if len(s) != Length {
		t.Fatalf("len = %d, want %d (%q)", len(s), Length, s)
	}
	if !Valid(s) {
		t.Errorf("Valid(%q) = false", s)
	}
	// The excluded letters are the whole reason for Crockford over plain base32.
	for _, bad := range []string{"I", "L", "O", "U"} {
		if strings.Contains(s, bad) {
			t.Errorf("id %q contains ambiguous character %q", s, bad)
		}
	}
}

func TestNewIsUnique(t *testing.T) {
	t.Parallel()

	const n = 20000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		s := New()
		if seen[s] {
			t.Fatalf("duplicate id after %d generations: %q", i, s)
		}
		seen[s] = true
	}
}

// Sortability is the property that justifies ULID over a random string: audit
// entries and request IDs must order by identifier alone.
func TestLexicographicOrderMatchesTimeOrder(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	times := []time.Time{
		base,
		base.Add(1 * time.Millisecond),
		base.Add(500 * time.Millisecond),
		base.Add(time.Hour),
		base.Add(365 * 24 * time.Hour),
	}

	ids := make([]string, len(times))
	for i, tm := range times {
		s, err := NewAt(tm)
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		ids[i] = s
	}

	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)

	for i := range ids {
		if ids[i] != sorted[i] {
			t.Fatalf("lexicographic order does not match chronological order\n got: %v\nwant: %v", sorted, ids)
		}
	}
}

func TestTimeRoundTrip(t *testing.T) {
	t.Parallel()

	// Truncate to milliseconds: that is the encoded resolution.
	want := time.Now().Truncate(time.Millisecond)
	s, err := NewAt(want)
	if err != nil {
		t.Fatalf("NewAt: %v", err)
	}

	got, err := Time(s)
	if err != nil {
		t.Fatalf("Time: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("Time = %v, want %v", got, want)
	}
}

func TestValid(t *testing.T) {
	t.Parallel()

	valid := New()
	tests := []struct {
		name  string
		in    string
		valid bool
	}{
		{"generated", valid, true},
		{"lowercase accepted", strings.ToLower(valid), true},
		{"empty", "", false},
		{"too short", valid[:25], false},
		{"too long", valid + "X", false},
		// The reason Valid exists: these are what a log-injection attempt looks
		// like arriving in an X-Request-ID header.
		{"newline injection", "01ARZ3NDEKTSV4RRFFQ69G5FA\n", false},
		{"json injection", `01ARZ3NDEKTSV4RRFFQ69G5F"}`, false},
		{"path traversal", "../../../../etc/passwd----", false},
		{"ambiguous letter I", strings.Repeat("I", 26), false},
		{"ambiguous letter O", strings.Repeat("O", 26), false},
		{"spaces", strings.Repeat(" ", 26), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Valid(tc.in); got != tc.valid {
				t.Errorf("Valid(%q) = %v, want %v", tc.in, got, tc.valid)
			}
		})
	}
}

func TestTimeRejectsMalformed(t *testing.T) {
	t.Parallel()

	if _, err := Time("not-an-id"); err == nil {
		t.Error("Time on a malformed id returned nil error")
	}
}

// Request IDs are minted from many goroutines at once, so generation must be
// safe under concurrency.
func TestNewIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	const goroutines, each = 16, 500

	var mu sync.Mutex
	seen := make(map[string]bool, goroutines*each)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]string, each)
			for i := range local {
				local[i] = New()
			}
			mu.Lock()
			defer mu.Unlock()
			for _, s := range local {
				if seen[s] {
					t.Errorf("duplicate id across goroutines: %q", s)
				}
				seen[s] = true
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*each {
		t.Errorf("got %d unique ids, want %d", len(seen), goroutines*each)
	}
}

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New()
	}
}
