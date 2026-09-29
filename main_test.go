package main

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestWaitForShutdownReturnsRuntimeError(t *testing.T) {
	want := errors.New("API listener failed")
	signals := make(chan os.Signal, 1)
	runtimeErrors := make(chan error, 1)
	runtimeErrors <- want

	if got := waitForShutdown(signals, runtimeErrors); !errors.Is(got, want) {
		t.Fatalf("waitForShutdown() = %v, want %v", got, want)
	}
}

func TestWaitForShutdownReturnsNilForSignal(t *testing.T) {
	signals := make(chan os.Signal, 1)
	runtimeErrors := make(chan error, 1)
	signals <- syscall.SIGTERM

	if got := waitForShutdown(signals, runtimeErrors); got != nil {
		t.Fatalf("waitForShutdown() = %v, want nil", got)
	}
}
