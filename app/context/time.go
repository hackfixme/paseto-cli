package context

import "time"

// TimeSource is the source of time information.
type TimeSource interface {
	Now() time.Time
}

// MockTimeSource is an implementation of TimeSource that always returns a fixed time T.
type MockTimeSource struct {
	T time.Time
}

// Now returns the stored fixed time.
func (t *MockTimeSource) Now() time.Time {
	return t.T
}
