package agent

import (
	"math/rand/v2"
	"time"
)

// backoff is full-jitter exponential backoff: each delay is drawn uniformly
// from zero to an envelope that doubles from min up to max.
type backoff struct {
	min, max time.Duration
	level    int
	// jitter returns a uniform duration in [0, n].
	jitter func(n time.Duration) time.Duration
}

// envelope is the upper bound of the next delay.
func (b *backoff) envelope() time.Duration {
	d := b.min
	for i := 0; i < b.level && d < b.max; i++ {
		d *= 2
	}
	if d > b.max || d <= 0 {
		d = b.max
	}
	return d
}

// next returns the delay before the next attempt and raises the envelope
// for the attempt after it.
func (b *backoff) next() time.Duration {
	env := b.envelope()
	if env < b.max {
		b.level++
	}
	return b.jitter(env)
}

// reset drops the envelope back to min. It is called only after a session
// that stayed up, never after a Bye.
func (b *backoff) reset() { b.level = 0 }

// uniformJitter returns a uniform duration in [0, n].
func uniformJitter(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	return rand.N(n + 1)
}
