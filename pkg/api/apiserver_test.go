package api

import (
	"bytes"
	"io"
	"middleware/pkg/modules"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestDashboardResponseDoesNotExposeAPIToken(t *testing.T) {
	server := NewServer("127.0.0.1:0", "server-secret-token", nil, NewWSHub("server-secret-token"), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	res := httptest.NewRecorder()
	server.router.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	if bytes.Contains(res.Body.Bytes(), []byte("server-secret-token")) {
		t.Fatal("dashboard response exposes the API token")
	}
}

func TestManagementHTTPServerTimeouts(t *testing.T) {
	server := NewServer("127.0.0.1:0", "token", nil, NewWSHub("token"), nil, nil)
	if server.httpSrv == nil {
		t.Fatal("management HTTP server was not initialized")
	}

	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "read header", got: server.httpSrv.ReadHeaderTimeout, want: apiReadHeaderTimeout},
		{name: "read", got: server.httpSrv.ReadTimeout, want: apiReadTimeout},
		{name: "write", got: server.httpSrv.WriteTimeout, want: apiWriteTimeout},
		{name: "idle", got: server.httpSrv.IdleTimeout, want: apiIdleTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want || tc.got <= 0 {
				t.Fatalf("timeout = %s, want positive %s", tc.got, tc.want)
			}
		})
	}
}

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

func TestBlocklistUploadRejectsOversizedBody(t *testing.T) {
	server := NewServer("127.0.0.1:0", "token", nil, NewWSHub("token"), nil, nil)

	// Stream the body instead of buffering it, so the test does not itself
	// allocate the oversized payload it is trying to reject.
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		part, err := mw.CreateFormFile("file", "oversized.txt")
		if err != nil {
			return
		}
		chunk := bytes.Repeat([]byte("a"), 1<<20)
		for range (maxUploadBodyBytes / (1 << 20)) + 2 {
			if _, err := part.Write(chunk); err != nil {
				return
			}
		}
		mw.Close()
	}()

	req := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/sources/upload", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer token")
	res := httptest.NewRecorder()
	server.router.ServeHTTP(res, req)

	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusRequestEntityTooLarge)
	}
}

// uploadBlocklist posts a single-file blocklist upload to the API.
func uploadBlocklist(t *testing.T, server *Server, id, filename, content string) *httptest.ResponseRecorder {
	t.Helper()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("id", id); err != nil {
		t.Fatalf("write id field: %v", err)
	}
	if err := mw.WriteField("name", id+"-list"); err != nil {
		t.Fatalf("write name field: %v", err)
	}
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/sources/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer token")
	res := httptest.NewRecorder()
	server.router.ServeHTTP(res, req)
	return res
}

func newUploadServer(t *testing.T) *Server {
	t.Helper()

	dir := t.TempDir()
	t.Chdir(dir)

	configPath := filepath.Join(dir, "blocklists.yaml")
	if err := os.WriteFile(configPath, []byte("version: \"1.0\"\nsources: []\n"), 0o600); err != nil {
		t.Fatalf("write blocklist config: %v", err)
	}
	mgr, err := modules.NewBlocklistManagerModule(configPath)
	if err != nil {
		t.Fatalf("build blocklist manager: %v", err)
	}
	return NewServer("127.0.0.1:0", "token", nil, NewWSHub("token"), nil, mgr)
}

func TestBlocklistUploadStoresBySourceID(t *testing.T) {
	server := newUploadServer(t)

	// Two distinct lists that happen to share an original filename must not
	// clobber each other's stored copy.
	if res := uploadBlocklist(t, server, "alpha", "shared.txt", "alpha.example\n"); res.Code != http.StatusCreated {
		t.Fatalf("alpha upload status = %d, want %d", res.Code, http.StatusCreated)
	}
	if res := uploadBlocklist(t, server, "beta", "shared.txt", "beta.example\n"); res.Code != http.StatusCreated {
		t.Fatalf("beta upload status = %d, want %d", res.Code, http.StatusCreated)
	}

	alpha, err := os.ReadFile(filepath.Join("uploads", "alpha.txt"))
	if err != nil {
		t.Fatalf("read alpha file: %v", err)
	}
	if string(alpha) != "alpha.example\n" {
		t.Fatalf("alpha.txt = %q, want %q; a second upload overwrote it", alpha, "alpha.example\n")
	}
	beta, err := os.ReadFile(filepath.Join("uploads", "beta.txt"))
	if err != nil {
		t.Fatalf("read beta file: %v", err)
	}
	if string(beta) != "beta.example\n" {
		t.Fatalf("beta.txt = %q, want %q", beta, "beta.example\n")
	}
}

func TestBlocklistUploadReusesPathForSameSourceID(t *testing.T) {
	server := newUploadServer(t)

	if res := uploadBlocklist(t, server, "alpha", "first.txt", "old.example\n"); res.Code != http.StatusCreated {
		t.Fatalf("first upload status = %d, want %d", res.Code, http.StatusCreated)
	}
	// Re-uploading the same id is an intentional update of that list.
	if res := uploadBlocklist(t, server, "alpha", "second.txt", "new.example\n"); res.Code != http.StatusCreated {
		t.Fatalf("second upload status = %d, want %d", res.Code, http.StatusCreated)
	}

	got, err := os.ReadFile(filepath.Join("uploads", "alpha.txt"))
	if err != nil {
		t.Fatalf("read alpha file: %v", err)
	}
	if string(got) != "new.example\n" {
		t.Fatalf("alpha.txt = %q, want %q", got, "new.example\n")
	}
}

func TestBlocklistUploadRejectsInvalidSourceID(t *testing.T) {
	server := newUploadServer(t)

	for _, id := range []string{"../escape", "a/b", ".hidden", "UPPER", ""} {
		t.Run(id, func(t *testing.T) {
			res := uploadBlocklist(t, server, id, "list.txt", "x.example\n")
			if res.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
			}
		})
	}

	entries, err := os.ReadDir("uploads")
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read uploads dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("uploads dir has %d entries after rejected ids, want 0", len(entries))
	}
}
