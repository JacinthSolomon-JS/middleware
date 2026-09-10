package pipeline

import (
	"context"
	"fmt"
	"sync"
)

type Engine struct {
	mu      sync.RWMutex
	modules []SecurityModule
}

func NewEngine() *Engine {
	return &Engine{
		modules: make([]SecurityModule, 0),
	}
}

func (e *Engine) RegisterModule(mod SecurityModule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules = append(e.modules, mod)
	fmt.Printf("[Pipeline Engine] Loaded module: %s\n", mod.Name())
}

func (e *Engine) Process(ctx context.Context, tctx *TrafficContext) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, mod := range e.modules {
		stop, err := mod.Inspect(ctx, tctx)
		if err != nil {
			fmt.Printf("[ERROR] Module %s failed: %v\n", mod.Name(), err)
			continue
		}
		if stop {
			break
		}
	}
}
