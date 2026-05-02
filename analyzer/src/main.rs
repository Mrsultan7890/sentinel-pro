// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use rayon::prelude::*;

#[derive(Deserialize, Debug)]
struct CollectedData {
    target: String,
    scraped_data: Vec<ScrapedItem>,
    entities: Entities,
    timestamp: f64,
}

#[derive(Deserialize, Debug)]
struct ScrapedItem {
    url: String,
    content: String,
    status: String,
}

#[derive(Deserialize, Debug)]
struct Entities {
    emails: Vec<String>,
    phones: Vec<String>,
    usernames: Vec<String>,
    urls: Vec<String>,
    locations: Vec<String>,
    names: Vec<String>,
}

#[derive(Serialize, Debug)]
struct CorrelationResult {
    username_patterns: Vec<UsernamePattern>,
    email_correlations: Vec<EmailCorrelation>,
    content_similarity: f64,
    cross_platform_matches: Vec<CrossPlatformMatch>,
    risk_indicators: Vec<RiskIndicator>,
}

#[derive(Serialize, Debug)]
struct UsernamePattern {
    username: String,
    pattern_type: String,
    confidence: f64,
}

#[derive(Serialize, Debug)]
struct EmailCorrelation {
    email: String,
    domain: String,
    related_usernames: Vec<String>,
}

#[derive(Serialize, Debug)]
struct CrossPlatformMatch {
    entity1: String,
    entity2: String,
    match_type: String,
    confidence: f64,
}

#[derive(Serialize, Debug)]
struct RiskIndicator {
    indicator_type: String,
    description: String,
    severity: String,
    evidence: String,
}

struct Analyzer {
    data: CollectedData,
}

impl Analyzer {
    fn new(data: CollectedData) -> Self {
        Self { data }
    }

    fn analyze(&self) -> CorrelationResult {
        let username_patterns = self.analyze_username_patterns();
        let email_correlations = self.analyze_email_correlations();
        let content_similarity = self.calculate_content_similarity();
        let cross_platform_matches = self.find_cross_platform_matches();
        let risk_indicators = self.identify_risk_indicators();

        CorrelationResult {
            username_patterns,
            email_correlations,
            content_similarity,
            cross_platform_matches,
            risk_indicators,
        }
    }

    fn analyze_username_patterns(&self) -> Vec<UsernamePattern> {
        self.data.entities.usernames
            .par_iter()
            .map(|username| {
                let pattern_type = self.classify_username_pattern(username);
                let confidence = self.calculate_username_confidence(username);
                
                UsernamePattern {
                    username: username.clone(),
                    pattern_type,
                    confidence,
                }
            })
            .collect()
    }

    fn classify_username_pattern(&self, username: &str) -> String {
        let clean_username = username.trim_start_matches('@');
        
        if clean_username.contains(char::is_numeric) && clean_username.contains(char::is_alphabetic) {
            "alphanumeric".to_string()
        } else if clean_username.chars().all(char::is_alphabetic) {
            "alphabetic".to_string()
        } else if clean_username.contains('_') || clean_username.contains('-') {
            "separated".to_string()
        } else {
            "other".to_string()
        }
    }

    fn calculate_username_confidence(&self, username: &str) -> f64 {
        let clean_username = username.trim_start_matches('@');
        let length = clean_username.len();
        
        // Confidence based on username characteristics
        let mut confidence: f64 = 0.5;
        
        if length >= 3 && length <= 15 {
            confidence += 0.2;
        }
        
        if clean_username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            confidence += 0.2;
        }
        
        // Check if username appears in multiple contexts
        let appearances = self.data.scraped_data
            .iter()
            .filter(|item| item.content.contains(clean_username))
            .count();
        
        if appearances > 1 {
            confidence += 0.1;
        }
        
        confidence.min(1.0)
    }

    fn analyze_email_correlations(&self) -> Vec<EmailCorrelation> {
        self.data.entities.emails
            .par_iter()
            .map(|email| {
                let domain = email.split('@').nth(1).unwrap_or("").to_string();
                let email_prefix = email.split('@').next().unwrap_or("");
                
                let related_usernames = self.data.entities.usernames
                    .iter()
                    .filter(|username| {
                        let clean_username = username.trim_start_matches('@');
                        clean_username.contains(email_prefix) || email_prefix.contains(clean_username)
                    })
                    .cloned()
                    .collect();

                EmailCorrelation {
                    email: email.clone(),
                    domain,
                    related_usernames,
                }
            })
            .collect()
    }

    fn calculate_content_similarity(&self) -> f64 {
        if self.data.scraped_data.len() < 2 {
            return 0.0;
        }

        let contents: Vec<&str> = self.data.scraped_data
            .iter()
            .map(|item| item.content.as_str())
            .collect();

        // Simple word-based similarity
        let mut total_similarity = 0.0;
        let mut comparisons = 0;

        for i in 0..contents.len() {
            for j in (i + 1)..contents.len() {
                let similarity = self.calculate_text_similarity(contents[i], contents[j]);
                total_similarity += similarity;
                comparisons += 1;
            }
        }

        if comparisons > 0 {
            total_similarity / comparisons as f64
        } else {
            0.0
        }
    }

    fn calculate_text_similarity(&self, text1: &str, text2: &str) -> f64 {
        let words1: std::collections::HashSet<&str> = text1.split_whitespace().collect();
        let words2: std::collections::HashSet<&str> = text2.split_whitespace().collect();
        
        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();
        
        if union > 0 {
            intersection as f64 / union as f64
        } else {
            0.0
        }
    }

    fn find_cross_platform_matches(&self) -> Vec<CrossPlatformMatch> {
        let mut matches = Vec::new();
        
        // Email-Username matches
        for email in &self.data.entities.emails {
            let email_prefix = email.split('@').next().unwrap_or("");
            for username in &self.data.entities.usernames {
                let clean_username = username.trim_start_matches('@');
                if email_prefix.to_lowercase() == clean_username.to_lowercase() {
                    matches.push(CrossPlatformMatch {
                        entity1: email.clone(),
                        entity2: username.clone(),
                        match_type: "email_username_exact".to_string(),
                        confidence: 0.9,
                    });
                } else if email_prefix.contains(clean_username) || clean_username.contains(email_prefix) {
                    matches.push(CrossPlatformMatch {
                        entity1: email.clone(),
                        entity2: username.clone(),
                        match_type: "email_username_partial".to_string(),
                        confidence: 0.6,
                    });
                }
            }
        }
        
        matches
    }

    fn identify_risk_indicators(&self) -> Vec<RiskIndicator> {
        let mut indicators = Vec::new();
        
        // Suspicious keywords
        let suspicious_keywords = vec![
            "hack", "exploit", "breach", "leak", "stolen", "fraud", "scam", 
            "phishing", "malware", "botnet", "ddos", "crack", "bypass"
        ];
        
        for item in &self.data.scraped_data {
            let content_lower = item.content.to_lowercase();
            for keyword in &suspicious_keywords {
                if content_lower.contains(keyword) {
                    indicators.push(RiskIndicator {
                        indicator_type: "suspicious_keyword".to_string(),
                        description: format!("Found suspicious keyword: {}", keyword),
                        severity: "medium".to_string(),
                        evidence: format!("URL: {}", item.url),
                    });
                }
            }
        }
        
        // Multiple email domains (potential identity fragmentation)
        let email_domains: std::collections::HashSet<String> = self.data.entities.emails
            .iter()
            .filter_map(|email| email.split('@').nth(1))
            .map(|domain| domain.to_string())
            .collect();
        
        if email_domains.len() > 3 {
            indicators.push(RiskIndicator {
                indicator_type: "multiple_email_domains".to_string(),
                description: format!("Found {} different email domains", email_domains.len()),
                severity: "high".to_string(),
                evidence: format!("Domains: {:?}", email_domains),
            });
        }
        
        // Excessive username variations
        if self.data.entities.usernames.len() > 5 {
            indicators.push(RiskIndicator {
                indicator_type: "excessive_usernames".to_string(),
                description: format!("Found {} usernames", self.data.entities.usernames.len()),
                severity: "medium".to_string(),
                evidence: format!("Count: {}", self.data.entities.usernames.len()),
            });
        }
        
        indicators
    }
}

fn main() -> io::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    
    let data: CollectedData = match serde_json::from_str(&input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("JSON parse error: {}", e);
            std::process::exit(1);
        }
    };
    
    let analyzer = Analyzer::new(data);
    let result = analyzer.analyze();
    
    match serde_json::to_string(&result) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("JSON serialize error: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}