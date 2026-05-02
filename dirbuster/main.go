// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DirResult struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	ContentLen  int64  `json:"content_length"`
	ContentType string `json:"content_type"`
	Risk        string `json:"risk"`
	Redirect    string `json:"redirect,omitempty"`
}

type Output struct {
	Domain  string      `json:"domain"`
	Results []DirResult `json:"results"`
	Total   int         `json:"total"`
	Scanned int         `json:"scanned"`
	Error   string      `json:"error,omitempty"`
}

// Risk classification by path keywords
var criticalKeywords = []string{
	".env", "wp-config", "config.php", "database", "backup",
	".git", "adminer", "phpinfo", "credentials", "secret",
	"passwd", "shadow", "id_rsa", "private", ".pem", ".key",
}
var highKeywords = []string{
	"admin", "phpmyadmin", "swagger", "graphql", "api-docs",
	"openapi", "debug", "console", "shell", "manager",
	"dashboard", "panel", "cpanel", "webmin",
}

func classifyRisk(path string, status int) string {
	p := strings.ToLower(path)
	if status == 200 {
		for _, kw := range criticalKeywords {
			if strings.Contains(p, kw) {
				return "CRITICAL"
			}
		}
		for _, kw := range highKeywords {
			if strings.Contains(p, kw) {
				return "HIGH"
			}
		}
		return "MEDIUM"
	}
	if status == 403 {
		for _, kw := range criticalKeywords {
			if strings.Contains(p, kw) {
				return "HIGH"
			}
		}
		return "LOW"
	}
	return "LOW"
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: dirbuster <domain> <wordlist> [threads] [extensions]")
		os.Exit(1)
	}

	domain   := os.Args[1]
	wordlist := os.Args[2]
	threads  := 50
	exts     := []string{""}

	if len(os.Args) >= 4 {
		if t, err := strconv.Atoi(os.Args[3]); err == nil && t > 0 {
			threads = t
		}
	}
	if len(os.Args) >= 5 {
		for _, e := range strings.Split(os.Args[4], ",") {
			e = strings.TrimSpace(e)
			if e != "" && !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			exts = append(exts, e)
		}
	}

	// Read wordlist
	f, err := os.Open(wordlist)
	if err != nil {
		out, _ := json.Marshal(Output{Domain: domain, Error: "wordlist not found: " + wordlist, Results: []DirResult{}})
		fmt.Println(string(out))
		return
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}

	// Build target list
	type target struct{ path, url string }
	var targets []target
	base := "https://" + domain
	for _, word := range words {
		for _, ext := range exts {
			path := "/" + word + ext
			targets = append(targets, target{path, base + path})
		}
	}

	// HTTP client — skip TLS verify, no redirects
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: threads,
			DisableKeepAlives:   false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	results := make([]DirResult, 0, 64)
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(tgt target) {
			defer wg.Done()
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", tgt.url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SentinelPro/2.1)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			// Only report interesting status codes
			if resp.StatusCode == 404 || resp.StatusCode == 400 {
				return
			}

			redirect := ""
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				redirect = resp.Header.Get("Location")
				// Skip redirects to same domain (e.g. http->https)
				if strings.Contains(redirect, domain) {
					return
				}
			}

			r := DirResult{
				Path:        tgt.path,
				URL:         tgt.url,
				StatusCode:  resp.StatusCode,
				ContentLen:  resp.ContentLength,
				ContentType: resp.Header.Get("Content-Type"),
				Risk:        classifyRisk(tgt.path, resp.StatusCode),
				Redirect:    redirect,
			}

			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(t)
	}

	wg.Wait()

	// Sort: CRITICAL first
	sorted := make([]DirResult, 0, len(results))
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		for _, r := range results {
			if r.Risk == sev {
				sorted = append(sorted, r)
			}
		}
	}

	out, _ := json.Marshal(Output{
		Domain:  domain,
		Results: sorted,
		Total:   len(sorted),
		Scanned: len(targets),
	})
	fmt.Println(string(out))
}
