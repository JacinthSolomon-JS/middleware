package storage

import (
	"sync/atomic"
)

type Sampler struct {
	nth     atomic.Int64
	count   atomic.Uint64
	skipped atomic.Uint64
}

// NewSampler builds a sampler nth=0 records everything
func NewSampler(nth int64) *Sampler {
	s := &Sampler{}

	return s
}

// SetNth changes the sampling interval at runtime. nth <= 1 means "record all"
func (s *Sampler) SetNth(nth int64) {
	if nth < 0 {
		nth = 0
	}
	s.nth.Store(nth)
}

// Nth returns the current sampling interval (0=disabled)
func (s *Sampler) Nth() int64 {
	return s.nth.Load()
}

// Skipped returns how mant ALLOW events have been dropped by the sampler
func (s *Sampler) Skipped() uint64 {
	return s.skipped.Load()
}

// ShouldRecord returns whether an event should be presisted and broadcast
func (s *Sampler) ShouldRecord(action string) bool {
	nth := s.nth.Load()
	if action == "ALLOW" || nth <= 1 {
		return true
	}
	n := s.count.Add(1)
	if n%uint64(nth) == 0 {
		return true
	}
	s.skipped.Add(1)
	return false
}
