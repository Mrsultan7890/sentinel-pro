/// Match & Replace engine — modifies requests/responses at proxy level
/// Rules loaded from Python via IPC command: set_mr_rules

use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MrRule {
    pub id:        u32,
    pub match_str: String,
    pub replace:   String,
    pub target:    String,   // RequestHeader/RequestBody/ResponseHeader/ResponseBody/URL/Any
    pub rule_type: String,   // Literal/Regex
    pub enabled:   bool,
}

#[derive(Clone)]
pub struct MatchReplaceEngine {
    rules: Arc<DashMap<u32, MrRule>>,
}

impl MatchReplaceEngine {
    pub fn new() -> Self {
        Self { rules: Arc::new(DashMap::new()) }
    }

    pub fn set_rules(&self, rules: Vec<MrRule>) {
        self.rules.clear();
        for r in rules {
            self.rules.insert(r.id, r);
        }
    }

    pub fn apply_to_request(
        &self,
        url:     &mut String,
        headers: &mut Vec<(String, String)>,
        body:    &mut Vec<u8>,
    ) {
        for entry in self.rules.iter() {
            let rule = entry.value();
            if !rule.enabled { continue; }
            match rule.target.as_str() {
                "URL" | "Any" => {
                    *url = self.do_replace(&rule.match_str, &rule.replace, &rule.rule_type, url);
                }
                "RequestHeader" | "Any" => {
                    for (_, v) in headers.iter_mut() {
                        *v = self.do_replace(&rule.match_str, &rule.replace, &rule.rule_type, v);
                    }
                }
                "RequestBody" | "Any" => {
                    let s = String::from_utf8_lossy(body).to_string();
                    let replaced = self.do_replace(&rule.match_str, &rule.replace, &rule.rule_type, &s);
                    *body = replaced.into_bytes();
                }
                _ => {}
            }
        }
    }

    pub fn apply_to_response(
        &self,
        headers: &mut Vec<(String, String)>,
        body:    &mut Vec<u8>,
    ) {
        for entry in self.rules.iter() {
            let rule = entry.value();
            if !rule.enabled { continue; }
            match rule.target.as_str() {
                "ResponseHeader" | "Any" => {
                    for (_, v) in headers.iter_mut() {
                        *v = self.do_replace(&rule.match_str, &rule.replace, &rule.rule_type, v);
                    }
                }
                "ResponseBody" | "Any" => {
                    let s = String::from_utf8_lossy(body).to_string();
                    let replaced = self.do_replace(&rule.match_str, &rule.replace, &rule.rule_type, &s);
                    *body = replaced.into_bytes();
                }
                _ => {}
            }
        }
    }

    fn do_replace(&self, match_str: &str, replace: &str, rule_type: &str, text: &str) -> String {
        if rule_type == "Regex" {
            if let Ok(re) = Regex::new(match_str) {
                return re.replace_all(text, replace).to_string();
            }
        }
        text.replace(match_str, replace)
    }
}
