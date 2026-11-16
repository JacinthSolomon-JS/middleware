package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html login.html css js
var files embed.FS

func Handler() http.Handler {
	sub, err := fs.Sub(files, ".")
	if err != nil {
		panic(err)
	}

	return http.FileServer(http.FS(sub))
}
