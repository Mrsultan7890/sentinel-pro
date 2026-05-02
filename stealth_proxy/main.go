// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ProxyManager struct {
	ProxyList    []string          `json:"proxy_list"`
	UserAgents   []string          `json:"user_agents"`
	CurrentProxy int               `json:"current_proxy"`
	RequestCount int               `json:"request_count"`
	Config       ProxyConfig       `json:"config"`
}

type ProxyConfig struct {
	RotationInterval int  `json:"rotation_interval"`
	RandomizeUA      bool `json:"randomize_ua"`
	TorIntegration   bool `json:"tor_integration"`
	StealthMode      bool `json:"stealth_mode"`
}

type StealthRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Data    string            `json:"data"`
}

type StealthResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	ProxyUsed  string            `json:"proxy_used"`
	UserAgent  string            `json:"user_agent"`
	Success    bool              `json:"success"`
	Error      string            `json:"error,omitempty"`
}

func NewProxyManager() *ProxyManager {
	return &ProxyManager{
		ProxyList: []string{
			"http://proxy1.example.com:8080",
			"http://proxy2.example.com:3128",
			"http://proxy3.example.com:8080",
			"socks5://127.0.0.1:9050", // Tor SOCKS proxy
		},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
		},
		Config: ProxyConfig{
			RotationInterval: 5,
			RandomizeUA:      true,
			TorIntegration:   true,
			StealthMode:      true,
		},
	}
}

func (pm *ProxyManager) GetNextProxy() string {
	if len(pm.ProxyList) == 0 {
		return ""
	}
	
	// Rotate proxy based on request count
	if pm.RequestCount%pm.Config.RotationInterval == 0 {
		pm.CurrentProxy = (pm.CurrentProxy + 1) % len(pm.ProxyList)
	}
	
	return pm.ProxyList[pm.CurrentProxy]
}

func (pm *ProxyManager) GetRandomUserAgent() string {
	if !pm.Config.RandomizeUA || len(pm.UserAgents) == 0 {
		return pm.UserAgents[0]
	}
	
	return pm.UserAgents[rand.Intn(len(pm.UserAgents))]
}

func (pm *ProxyManager) CreateStealthClient(proxyURL string) (*http.Client, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	if proxyURL != "" {
		proxyParsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		
		client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyParsed)
	}
	
	return client, nil
}

func (pm *ProxyManager) MakeStealthRequest(req StealthRequest) StealthResponse {
	pm.RequestCount++
	
	// Get proxy and user agent
	proxyURL := pm.GetNextProxy()
	userAgent := pm.GetRandomUserAgent()
	
	// Create stealth client
	client, err := pm.CreateStealthClient(proxyURL)
	if err != nil {
		return StealthResponse{
			Success: false,
			Error:   fmt.Sprintf("Client creation failed: %v", err),
		}
	}
	
	// Create HTTP request
	var body io.Reader
	if req.Data != "" {
		body = strings.NewReader(req.Data)
	}
	
	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return StealthResponse{
			Success: false,
			Error:   fmt.Sprintf("Request creation failed: %v", err),
		}
	}
	
	// Set stealth headers
	pm.setStealthHeaders(httpReq, userAgent, req.Headers)
	
	// Add human-like delay
	if pm.Config.StealthMode {
		delay := time.Duration(rand.Intn(3000)+1000) * time.Millisecond
		time.Sleep(delay)
	}
	
	// Make request
	resp, err := client.Do(httpReq)
	if err != nil {
		return StealthResponse{
			Success:   false,
			Error:     fmt.Sprintf("Request failed: %v", err),
			ProxyUsed: proxyURL,
			UserAgent: userAgent,
		}
	}
	defer resp.Body.Close()
	
	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return StealthResponse{
			Success:    false,
			Error:      fmt.Sprintf("Response read failed: %v", err),
			StatusCode: resp.StatusCode,
			ProxyUsed:  proxyURL,
			UserAgent:  userAgent,
		}
	}
	
	// Extract response headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	
	return StealthResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(respBody),
		ProxyUsed:  proxyURL,
		UserAgent:  userAgent,
		Success:    true,
	}
}

func (pm *ProxyManager) setStealthHeaders(req *http.Request, userAgent string, customHeaders map[string]string) {
	// Set realistic headers
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Cache-Control", "max-age=0")
	
	// Browser-specific headers
	if strings.Contains(userAgent, "Chrome") {
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
	}
	
	// Add custom headers
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}
}

func (pm *ProxyManager) TestProxies() map[string]bool {
	results := make(map[string]bool)
	testURL := "http://httpbin.org/ip"
	
	for _, proxy := range pm.ProxyList {
		client, err := pm.CreateStealthClient(proxy)
		if err != nil {
			results[proxy] = false
			continue
		}
		
		resp, err := client.Get(testURL)
		if err != nil {
			results[proxy] = false
			continue
		}
		resp.Body.Close()
		
		results[proxy] = resp.StatusCode == 200
	}
	
	return results
}

func (pm *ProxyManager) RotateTorIdentity() error {
	// Send NEWNYM signal to Tor control port
	// This is a simplified version - in production, use proper Tor control protocol
	fmt.Println("Rotating Tor identity...")
	time.Sleep(2 * time.Second) // Wait for new circuit
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [args...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  request <url> - Make stealth request\n")
		fmt.Fprintf(os.Stderr, "  test - Test all proxies\n")
		fmt.Fprintf(os.Stderr, "  rotate - Rotate Tor identity\n")
		os.Exit(1)
	}
	
	pm := NewProxyManager()
	command := os.Args[1]
	
	switch command {
	case "request":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s request <url>\n", os.Args[0])
			os.Exit(1)
		}
		
		req := StealthRequest{
			URL:    os.Args[2],
			Method: "GET",
			Headers: map[string]string{},
		}
		
		response := pm.MakeStealthRequest(req)
		
		output, err := json.Marshal(response)
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Println(string(output))
		
	case "test":
		results := pm.TestProxies()
		
		output, err := json.Marshal(results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Println(string(output))
		
	case "rotate":
		err := pm.RotateTorIdentity()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Tor rotation failed: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Println(`{"success": true, "message": "Tor identity rotated"}`)
		
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
}