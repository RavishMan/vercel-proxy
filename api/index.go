package api

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

// Only https requests to ALLOWED_HOSTS (comma-separated) under
// ALLOWED_PATH_PREFIX are proxied. Without ALLOWED_HOSTS every request is
// rejected.
const defaultPathPrefix = "/sub/"

var (
	schemeRe = regexp.MustCompile(`^/*(https?:)/*`)

	client = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !allowedTarget(req.URL) {
				return errors.New("redirect to a disallowed target")
			}
			return nil
		},
	}
)

func allowedHosts() map[string]bool {
	hosts := map[string]bool{}
	for _, h := range strings.Split(os.Getenv("ALLOWED_HOSTS"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts[h] = true
		}
	}
	return hosts
}

func pathPrefix() string {
	if p := os.Getenv("ALLOWED_PATH_PREFIX"); p != "" {
		return p
	}
	return defaultPathPrefix
}

func allowedTarget(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil {
		return false
	}
	if p := u.Port(); p != "" && p != "443" {
		return false
	}
	if !allowedHosts()[strings.ToLower(u.Hostname())] {
		return false
	}
	// Reject dot segments and duplicate slashes instead of rewriting them.
	clean := path.Clean(u.Path)
	if u.Path != clean && u.Path != clean+"/" {
		return false
	}
	prefix := pathPrefix()
	return strings.HasPrefix(clean+"/", prefix) && clean+"/" != prefix
}

func Handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("panic: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}()

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw := schemeRe.ReplaceAllString(r.URL.Path, "$1//")
	if !strings.HasPrefix(raw, "http") {
		http.NotFound(w, r)
		return
	}
	target, err := url.Parse(raw)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	target.RawQuery = r.URL.RawQuery
	if !allowedTarget(target) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for k, v := range r.Header {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("upstream error: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("copy error: %v", err)
	}
}
