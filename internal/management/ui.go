package management

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// The console is embedded rather than read from disk: a node has one binary and
// one config, and a UI that could be swapped out underneath the management
// plane would be a way to serve script from a privileged origin.
//
//go:embed ui/index.html ui/app.js ui/style.css
var uiFS embed.FS

// contentSecurityPolicy locks the console to what it actually is.
//
// Everything it loads is served from this origin, so there is no exception to
// make for a CDN. 'unsafe-inline' is absent deliberately: it is what turns an
// injected record value into executing script, and the console renders every
// value with textContent so it never needs it.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'"

// uiHandler serves the console.
func uiHandler() (http.Handler, error) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return nil, err
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)

		switch {
		case r.URL.Path == "/" || r.URL.Path == "/index.html":
			// The console is a single page; it holds no secrets and needs no
			// session to load, because every byte of data behind it does.
			w.Header().Set("Cache-Control", "no-store")
			serveFile(w, r, sub, "index.html")
		case strings.HasPrefix(r.URL.Path, "/ui/"):
			r2 := r.Clone(r.Context())
			r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/ui")
			files.ServeHTTP(w, r2)
		default:
			http.NotFound(w, r)
		}
	}), nil
}

func serveFile(w http.ResponseWriter, r *http.Request, sub fs.FS, name string) {
	f, err := sub.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		http.Error(w, "stat failed", http.StatusInternalServerError)
		return
	}
	rs, ok := f.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	})
	if !ok {
		http.Error(w, "not seekable", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), rs)
}

// setSecurityHeaders applies the headers every management response carries.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	// Without this a response the browser decides is HTML — a record value, an
	// error string — could be rendered as a page from this origin.
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// The admin plane has nothing to gain from being framed, and being framed
	// is how clickjacking works.
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}
