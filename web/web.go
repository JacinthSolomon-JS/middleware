package web

import (
	"bytes"
	_ "embed"
)

//go:embed index.html
var IndexHTML []byte

func DashboardHTML(token string) []byte {
	return bytes.ReplaceAll(IndexHTML, []byte("API_TOKEN"), []byte(token))
}
