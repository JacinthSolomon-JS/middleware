package web

import (
	_ "embed"
)

//go:embed index.html
var IndexHTML []byte

// DashboardHTML returns the static dashboard. Authentication credentials are
// deliberately never rendered into the page; the operator supplies a token at
// runtime and the browser retains it only for the current tab session.
func DashboardHTML() []byte {
	return IndexHTML
}
