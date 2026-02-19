package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type SessionData struct {
	Target        string        `json:"target"`
	CollectedData CollectedData `json:"collected_data"`
	Analysis      Analysis      `json:"analysis"`
}

type CollectedData struct {
	Target      string            `json:"target"`
	ScrapedData []ScrapedItem     `json:"scraped_data"`
	Entities    map[string][]string `json:"entities"`
	Timestamp   float64           `json:"timestamp"`
}

type ScrapedItem struct {
	URL     string `json:"url"`
	Content string `json:"content"`
	Status  string `json:"status"`
}

type Analysis struct {
	Correlations        map[string]interface{} `json:"correlations"`
	BehavioralPatterns  map[string]interface{} `json:"behavioral_patterns"`
	Connections         []Connection           `json:"connections"`
	RiskScore          float64                `json:"risk_score"`
	Timestamp          float64                `json:"timestamp"`
}

type Connection struct {
	Type       string    `json:"type"`
	Entities   []string  `json:"entities"`
	Confidence float64   `json:"confidence"`
}

type Prediction struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Priority    string  `json:"priority"`
	Confidence  float64 `json:"confidence"`
	NextSteps   []string `json:"next_steps"`
}

type PredictiveEngine struct {
	sessionData SessionData
}

func NewPredictiveEngine(data SessionData) *PredictiveEngine {
	return &PredictiveEngine{sessionData: data}
}

func (pe *PredictiveEngine) GeneratePredictions() []Prediction {
	var predictions []Prediction
	
	// Analyze entities for prediction opportunities
	predictions = append(predictions, pe.predictFromEntities()...)
	
	// Analyze risk score for escalation predictions
	predictions = append(predictions, pe.predictFromRiskScore()...)
	
	// Analyze connections for network expansion
	predictions = append(predictions, pe.predictFromConnections()...)
	
	// Analyze content patterns
	predictions = append(predictions, pe.predictFromContent()...)
	
	return predictions
}

func (pe *PredictiveEngine) predictFromEntities() []Prediction {
	var predictions []Prediction
	entities := pe.sessionData.CollectedData.Entities
	
	// Email-based predictions
	if emails, exists := entities["emails"]; exists && len(emails) > 0 {
		for _, email := range emails {
			domain := pe.extractDomain(email)
			if domain != "" {
				predictions = append(predictions, Prediction{
					Type:        "domain_investigation",
					Description: fmt.Sprintf("Investigate domain '%s' for additional accounts", domain),
					Priority:    "high",
					Confidence:  0.8,
					NextSteps: []string{
						fmt.Sprintf("Search for other accounts using domain: %s", domain),
						"Check domain registration information",
						"Look for subdomains and related services",
					},
				})
			}
		}
		
		// Multiple emails suggest identity fragmentation
		if len(emails) > 2 {
			predictions = append(predictions, Prediction{
				Type:        "identity_fragmentation",
				Description: "Multiple email addresses suggest deliberate identity fragmentation",
				Priority:    "critical",
				Confidence:  0.9,
				NextSteps: []string{
					"Cross-reference all email addresses",
					"Check for common registration patterns",
					"Investigate temporal usage patterns",
				},
			})
		}
	}
	
	// Username-based predictions
	if usernames, exists := entities["usernames"]; exists && len(usernames) > 0 {
		commonPlatforms := []string{"twitter.com", "github.com", "reddit.com", "instagram.com", "facebook.com"}
		
		for _, username := range usernames {
			cleanUsername := strings.TrimPrefix(username, "@")
			predictions = append(predictions, Prediction{
				Type:        "username_expansion",
				Description: fmt.Sprintf("Search for username '%s' across additional platforms", cleanUsername),
				Priority:    "medium",
				Confidence:  0.7,
				NextSteps:   pe.generatePlatformSearchSteps(cleanUsername, commonPlatforms),
			})
		}
	}
	
	// Phone number predictions
	if phones, exists := entities["phones"]; exists && len(phones) > 0 {
		predictions = append(predictions, Prediction{
			Type:        "phone_investigation",
			Description: "Phone numbers found - investigate carrier and registration details",
			Priority:    "medium",
			Confidence:  0.6,
			NextSteps: []string{
				"Lookup phone number carrier information",
				"Check for VoIP vs mobile classification",
				"Search for phone number in data breaches",
			},
		})
	}
	
	return predictions
}

func (pe *PredictiveEngine) predictFromRiskScore() []Prediction {
	var predictions []Prediction
	riskScore := pe.sessionData.Analysis.RiskScore
	
	if riskScore >= 70 {
		predictions = append(predictions, Prediction{
			Type:        "high_risk_escalation",
			Description: "High risk score indicates potential threat actor - escalate investigation",
			Priority:    "critical",
			Confidence:  0.95,
			NextSteps: []string{
				"Conduct deep behavioral analysis",
				"Cross-reference with known threat databases",
				"Monitor for real-time activity",
				"Consider law enforcement notification",
			},
		})
	} else if riskScore >= 40 {
		predictions = append(predictions, Prediction{
			Type:        "medium_risk_monitoring",
			Description: "Medium risk score suggests continued monitoring required",
			Priority:    "high",
			Confidence:  0.7,
			NextSteps: []string{
				"Set up automated monitoring alerts",
				"Expand search to related entities",
				"Check for recent activity patterns",
			},
		})
	}
	
	return predictions
}

func (pe *PredictiveEngine) predictFromConnections() []Prediction {
	var predictions []Prediction
	connections := pe.sessionData.Analysis.Connections
	
	if len(connections) > 0 {
		// High-confidence connections suggest network analysis
		highConfidenceConnections := 0
		for _, conn := range connections {
			if conn.Confidence > 0.7 {
				highConfidenceConnections++
			}
		}
		
		if highConfidenceConnections > 0 {
			predictions = append(predictions, Prediction{
				Type:        "network_expansion",
				Description: "Strong connections found - expand investigation to connected entities",
				Priority:    "high",
				Confidence:  0.8,
				NextSteps: []string{
					"Investigate all connected entities individually",
					"Map the complete network topology",
					"Identify central nodes in the network",
					"Look for temporal correlation in activities",
				},
			})
		}
		
		// Multiple connection types suggest sophisticated operation
		connectionTypes := make(map[string]bool)
		for _, conn := range connections {
			connectionTypes[conn.Type] = true
		}
		
		if len(connectionTypes) > 2 {
			predictions = append(predictions, Prediction{
				Type:        "sophisticated_operation",
				Description: "Multiple connection types indicate sophisticated operational security",
				Priority:    "critical",
				Confidence:  0.85,
				NextSteps: []string{
					"Analyze operational security patterns",
					"Look for counter-surveillance measures",
					"Check for use of anonymization tools",
					"Investigate infrastructure patterns",
				},
			})
		}
	}
	
	return predictions
}

func (pe *PredictiveEngine) predictFromContent() []Prediction {
	var predictions []Prediction
	
	// Analyze scraped content for patterns
	contentSources := make(map[string]int)
	totalContent := 0
	
	for _, item := range pe.sessionData.CollectedData.ScrapedData {
		if item.Status == "success" && len(item.Content) > 0 {
			// Extract domain from URL
			domain := pe.extractDomainFromURL(item.URL)
			if domain != "" {
				contentSources[domain]++
			}
			totalContent++
		}
	}
	
	// If content found across multiple platforms
	if len(contentSources) > 2 {
		predictions = append(predictions, Prediction{
			Type:        "multi_platform_presence",
			Description: "Target has presence across multiple platforms - comprehensive analysis recommended",
			Priority:    "medium",
			Confidence:  0.6,
			NextSteps: []string{
				"Conduct platform-specific deep dives",
				"Look for cross-platform behavioral patterns",
				"Check for temporal activity correlation",
			},
		})
	}
	
	// If limited content found
	if totalContent < 3 {
		predictions = append(predictions, Prediction{
			Type:        "limited_footprint",
			Description: "Limited digital footprint detected - may indicate operational security or new identity",
			Priority:    "medium",
			Confidence:  0.7,
			NextSteps: []string{
				"Expand search terms and methodologies",
				"Check for recent account creation patterns",
				"Look for alternative spellings and variations",
				"Consider use of privacy tools or techniques",
			},
		})
	}
	
	return predictions
}

func (pe *PredictiveEngine) extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func (pe *PredictiveEngine) extractDomainFromURL(url string) string {
	// Simple domain extraction
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func (pe *PredictiveEngine) generatePlatformSearchSteps(username string, platforms []string) []string {
	var steps []string
	for _, platform := range platforms {
		steps = append(steps, fmt.Sprintf("Search %s for username: %s", platform, username))
	}
	return steps
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
	
	var sessionData SessionData
	if err := json.Unmarshal(input, &sessionData); err != nil {
		fmt.Fprintf(os.Stderr, "JSON unmarshal error: %v\n", err)
		os.Exit(1)
	}
	
	engine := NewPredictiveEngine(sessionData)
	predictions := engine.GeneratePredictions()
	
	output, err := json.Marshal(predictions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println(string(output))
}