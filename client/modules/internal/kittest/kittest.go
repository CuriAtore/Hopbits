// Package kittest provides test doubles for the node modules' tests.
package kittest

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/hopbits/client/modules/internal/kit"
)

// Clock is a fake clock. Sleep returns at once and moves the clock on, so
// waits between samples cost no real time and timings are exact.
type Clock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

// NewClock returns a fake clock at a fixed instant.
func NewClock() *Clock {
	return &Clock{now: time.Unix(1_800_000_000, 0)}
}

// Now returns the fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the fake time on by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Sleep records d and moves the fake time on by it, or returns ctx's error
// if ctx has ended.
func (c *Clock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	if d > 0 {
		c.now = c.now.Add(d)
	}
	return nil
}

// Sleeps returns the durations passed to Sleep, in order.
func (c *Clock) Sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.sleeps)
}

// Ticker returns a clock reading that moves on by step every time it is
// read, from any goroutine. Durations between readings are never zero and
// depend only on how many readings lie between them, so tests can check
// timing phases exactly whatever the host clock's resolution.
func Ticker(step time.Duration) func() time.Time {
	var mu sync.Mutex
	t := time.Unix(1_800_000_000, 0)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(step)
		return t
	}
}

// Kit returns the clock in the form the modules take.
func (c *Clock) Kit() kit.Clock {
	return kit.Clock{Now: c.Now, Sleep: c.Sleep}
}
