package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestResolverPreset(t *testing.T) {
	preset, ok := resolverPreset("cloudflare")
	if !ok {
		t.Fatal("cloudflare resolver preset was not found")
	}
	if preset.Address != "1.1.1.1:53" {
		t.Fatalf("unexpected cloudflare address: %s", preset.Address)
	}

	if _, ok := resolverPreset("does-not-exist"); ok {
		t.Fatal("unknown resolver preset unexpectedly resolved")
	}
}

func TestHostAllowList(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name string
		host string
		want int
	}{
		{name: "localhost", host: "localhost:8080", want: http.StatusNoContent},
		{name: "ipv4 loopback", host: "127.0.0.1:8080", want: http.StatusNoContent},
		{name: "ipv6 loopback", host: "[::1]:8080", want: http.StatusNoContent},
		{name: "external host", host: "gateway.example", want: http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(hostAllowList)
			router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
			req.Host = tc.host
			res := httptest.NewRecorder()
			router.ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("status = %d, want %d", res.Code, tc.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{authToken: "secret-token"}
	router := gin.New()
	router.Use(server.authRequired)
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "wrong", header: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "valid", header: "Bearer secret-token", want: http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			res := httptest.NewRecorder()
			router.ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("status = %d, want %d", res.Code, tc.want)
			}
		})
	}
}
