package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestDashboardHTMLDoesNotExposeServerToken(t *testing.T) {
	got := DashboardHTML()
	if bytes.Contains(got, []byte("test-token-123")) {
		t.Fatal("dashboard contains server authentication material")
	}
	if !bytes.Contains(got, []byte("gateway_api_token")) {
		t.Fatal("dashboard does not contain runtime session authentication")
	}
}

func TestEmbeddedDashboardContainsPrimaryViews(t *testing.T) {
	html := string(IndexHTML)
	for _, id := range []string{
		"view-overview",
		"view-analytics",
		"view-logs",
		"view-security",
		"view-privacy",
		"view-settings",
	} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("embedded dashboard is missing %s", id)
		}
	}

	for _, route := range []string{
		"/summary",
		"/logs",
		"/sources",
		"/blocklist",
		"/allowlist",
		"/ipblocklist",
		"/mode",
		"/resolver",
	} {
		if !strings.Contains(html, route) {
			t.Errorf("embedded dashboard does not reference API route %s", route)
		}
	}
}

func TestDashboardHasResponsiveAndAccessibleMetadata(t *testing.T) {
	html := string(IndexHTML)
	for _, want := range []string{
		`name="viewport"`,
		`<title>Sentinel Gateway</title>`,
		`type="search"`,
		`aria-label="Traffic chart"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("embedded dashboard is missing %q", want)
		}
	}
}
