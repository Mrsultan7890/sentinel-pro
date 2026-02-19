package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ScrapedData struct {
	URL     string `json:"url"`
	Content string `json:"content"`
	Status  string `json:"status"`
}

type Scraper struct {
	client    *http.Client
	userAgent string
	results   []ScrapedData
	mutex     sync.Mutex
}

func NewScraper() *Scraper {
	return &Scraper{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		results:   make([]ScrapedData, 0),
	}
}

func (s *Scraper) scrapeURL(url string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		s.addResult(ScrapedData{URL: url, Content: "", Status: fmt.Sprintf("error: %v", err)})
		return
	}
	
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	
	resp, err := s.client.Do(req)
	if err != nil {
		s.addResult(ScrapedData{URL: url, Content: "", Status: fmt.Sprintf("error: %v", err)})
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		s.addResult(ScrapedData{URL: url, Content: "", Status: fmt.Sprintf("http_error: %d", resp.StatusCode)})
		return
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.addResult(ScrapedData{URL: url, Content: "", Status: fmt.Sprintf("read_error: %v", err)})
		return
	}
	
	// Extract specific data for direct profile URLs
	content := string(body)
	extractedData := extractProfileData(url, content)
	
	// Increase content size limit for better data extraction
	if len(content) > 15000 {
		content = content[:15000]
	}
	
	result := ScrapedData{URL: url, Content: content, Status: "success"}
	
	// Add extracted profile data if available
	if extractedData != "" {
		result.Content = extractedData + "\n\n" + result.Content
	}
	
	s.addResult(result)
}

func (s *Scraper) addResult(result ScrapedData) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.results = append(s.results, result)
}

func (s *Scraper) generateSearchURLs(target string) []string {
	// Clean target for URL encoding
	cleanTarget := strings.ReplaceAll(target, " ", "+")
	quotedTarget := fmt.Sprintf("\"%s\"", cleanTarget)
	
	// Direct profile URLs first for better data extraction
	urls := []string{
		fmt.Sprintf("https://www.instagram.com/%s/", cleanTarget),
		fmt.Sprintf("https://twitter.com/%s", cleanTarget),
		fmt.Sprintf("https://www.youtube.com/@%s", cleanTarget),
		fmt.Sprintf("https://github.com/%s", cleanTarget),
		fmt.Sprintf("https://www.tiktok.com/@%s", cleanTarget),
		fmt.Sprintf("https://www.linkedin.com/in/%s", cleanTarget),
		fmt.Sprintf("https://www.facebook.com/%s", cleanTarget),
		// Search engines as fallback
		fmt.Sprintf("https://duckduckgo.com/html/?q=%s", cleanTarget),
		fmt.Sprintf("https://www.bing.com/search?q=%s", cleanTarget),
		fmt.Sprintf("https://duckduckgo.com/html/?q=%s+profile", quotedTarget),
		fmt.Sprintf("https://duckduckgo.com/html/?q=%s+social+media", quotedTarget),
	}
	
	// Platform-specific searches
	platforms := []string{
		"github.com", "reddit.com", "twitter.com", "instagram.com", 
		"linkedin.com", "facebook.com", "tiktok.com", "youtube.com",
		"discord.com", "telegram.org", "medium.com", "dev.to",
		"stackoverflow.com", "twitch.tv", "pinterest.com",
	}
	
	for _, platform := range platforms {
		urls = append(urls, fmt.Sprintf("https://duckduckgo.com/html/?q=site:%s+%s", platform, cleanTarget))
	}
	
	// Add username and email specific searches
	if isEmail(target) {
		urls = append(urls, fmt.Sprintf("https://duckduckgo.com/html/?q=%s+email+profile", quotedTarget))
	}
	
	if isUsername(target) {
		urls = append(urls, fmt.Sprintf("https://duckduckgo.com/html/?q=%s+username+handle", quotedTarget))
		urls = append(urls, fmt.Sprintf("https://duckduckgo.com/html/?q=@%s", cleanTarget))
	}
	
	return urls
}

func isEmail(target string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(target)
}

func isUsername(target string) bool {
	return strings.HasPrefix(target, "@") || (len(target) > 3 && len(target) < 20 && !strings.Contains(target, " "))
}

func (s *Scraper) scrapeTarget(target string) {
	urls := s.generateSearchURLs(target)
	
	var wg sync.WaitGroup
	
	for _, url := range urls {
		wg.Add(1)
		go s.scrapeURL(url, &wg)
		
		// Better rate limiting to avoid detection
		time.Sleep(time.Millisecond * 1000)
	}
	
	wg.Wait()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <target>\n", os.Args[0])
		os.Exit(1)
	}
	
	target := os.Args[1]
	scraper := NewScraper()
	
	scraper.scrapeTarget(target)
	
	// Output results as JSON
	output, err := json.Marshal(scraper.results)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println(string(output))
}
func extractProfileData(url, content string) string {
	var extracted []string
	
	// Instagram data extraction
	if strings.Contains(url, "instagram.com/") {
		// Extract follower count from meta description
		if match := regexp.MustCompile(`(\d+[KMB]?)\s*[Ff]ollowers`).FindStringSubmatch(content); len(match) > 1 {
			extracted = append(extracted, fmt.Sprintf("FOLLOWERS: %s", match[1]))
		}
		
		// Extract display name from title
		if match := regexp.MustCompile(`<title>([^|]+)`).FindStringSubmatch(content); len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" {
				extracted = append(extracted, fmt.Sprintf("DISPLAY_NAME: %s", name))
			}
		}
		
		// Extract bio from meta description
		if match := regexp.MustCompile(`<meta property="og:description" content="([^"]+)"`).FindStringSubmatch(content); len(match) > 1 {
			bio := strings.TrimSpace(match[1])
			if len(bio) > 20 {
				extracted = append(extracted, fmt.Sprintf("BIO: %s", bio))
			}
		}
	}
	
	// Twitter data extraction
	if strings.Contains(url, "twitter.com/") {
		// Extract display name
		if match := regexp.MustCompile(`<title>([^(]+)`).FindStringSubmatch(content); len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" && !strings.Contains(name, "Twitter") {
				extracted = append(extracted, fmt.Sprintf("DISPLAY_NAME: %s", name))
			}
		}
		
		// Extract follower count
		if match := regexp.MustCompile(`(\d+[KMB]?)\s*[Ff]ollowers`).FindStringSubmatch(content); len(match) > 1 {
			extracted = append(extracted, fmt.Sprintf("FOLLOWERS: %s", match[1]))
		}
	}
	
	// YouTube data extraction
	if strings.Contains(url, "youtube.com/@") {
		// Extract channel name
		if match := regexp.MustCompile(`<title>([^-]+)`).FindStringSubmatch(content); len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" {
				extracted = append(extracted, fmt.Sprintf("DISPLAY_NAME: %s", name))
			}
		}
		
		// Extract subscriber count
		if match := regexp.MustCompile(`(\d+[KMB]?)\s*subscribers`).FindStringSubmatch(content); len(match) > 1 {
			extracted = append(extracted, fmt.Sprintf("SUBSCRIBERS: %s", match[1]))
		}
	}
	
	// GitHub data extraction
	if strings.Contains(url, "github.com/") {
		// Extract name
		if match := regexp.MustCompile(`<title>([^(]+)`).FindStringSubmatch(content); len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" && !strings.Contains(name, "GitHub") {
				extracted = append(extracted, fmt.Sprintf("DISPLAY_NAME: %s", name))
			}
		}
		
		// Extract follower count
		if match := regexp.MustCompile(`(\d+)\s*followers`).FindStringSubmatch(content); len(match) > 1 {
			extracted = append(extracted, fmt.Sprintf("FOLLOWERS: %s", match[1]))
		}
		
		// Extract repository count
		if match := regexp.MustCompile(`(\d+)\s*repositories`).FindStringSubmatch(content); len(match) > 1 {
			extracted = append(extracted, fmt.Sprintf("REPOSITORIES: %s", match[1]))
		}
	}
	
	// TikTok data extraction
	if strings.Contains(url, "tiktok.com/@") {
		// Extract display name
		if match := regexp.MustCompile(`<title>([^|]+)`).FindStringSubmatch(content); len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" {
				extracted = append(extracted, fmt.Sprintf("DISPLAY_NAME: %s", name))
			}
		}
		
		// Extract follower count
		if match := regexp.MustCompile(`(\d+[KMB]?)\s*[Ff]ollowers`).FindStringSubmatch(content); len(match) > 1 {
			extracted = append(extracted, fmt.Sprintf("FOLLOWERS: %s", match[1]))
		}
	}
	
	// LinkedIn data extraction
	if strings.Contains(url, "linkedin.com/in/") {
		// Extract name
		if match := regexp.MustCompile(`<title>([^|]+)`).FindStringSubmatch(content); len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" {
				extracted = append(extracted, fmt.Sprintf("DISPLAY_NAME: %s", name))
			}
		}
		
		// Extract connections
		if match := regexp.MustCompile(`(\d+[KM]?)\s*connections`).FindStringSubmatch(content); len(match) > 1 {
			extracted = append(extracted, fmt.Sprintf("CONNECTIONS: %s", match[1]))
		}
	}
	
	// Facebook data extraction
	if strings.Contains(url, "facebook.com/") {
		// Extract name
		if match := regexp.MustCompile(`<title>([^|]+)`).FindStringSubmatch(content); len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" && !strings.Contains(name, "Facebook") {
				extracted = append(extracted, fmt.Sprintf("DISPLAY_NAME: %s", name))
			}
		}
	}
	
	// Extract emails and phone numbers from any platform
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	if emails := emailRegex.FindAllString(content, 5); len(emails) > 0 {
		for _, email := range emails {
			extracted = append(extracted, fmt.Sprintf("EMAIL: %s", email))
		}
	}
	
	phoneRegex := regexp.MustCompile(`(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	if phones := phoneRegex.FindAllString(content, 3); len(phones) > 0 {
		for _, phone := range phones {
			extracted = append(extracted, fmt.Sprintf("PHONE: %s", phone))
		}
	}
	
	if len(extracted) > 0 {
		return "EXTRACTED_DATA:\n" + strings.Join(extracted, "\n")
	}
	
	return ""
}