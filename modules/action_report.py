"""
Sentinel Action Report Generator
Groq se AI-powered remediation guide generate karta hai har finding ke liye.
"""

import os
import json
import logging

logger = logging.getLogger(__name__)

GROQ_MODEL = "llama-3.3-70b-versatile"
FALLBACK_MODEL = "llama-3.1-8b-instant"

SYSTEM_PROMPT = """You are a senior penetration tester and security engineer writing an action report for a client.
For each security finding provided, give a structured remediation guide.
Be specific, technical, and actionable. Use exact commands/code where possible.
Respond ONLY with valid JSON — no markdown, no extra text."""

USER_PROMPT_TEMPLATE = """Analyze these security findings and generate an action plan:

{findings_json}

For EACH finding, return a JSON array where each item has:
- "title": finding title (string)
- "severity": severity level (string)
- "what_it_is": 2-3 sentence explanation of what this vulnerability/issue is and why it's dangerous
- "how_to_reproduce": step-by-step instructions to reproduce/verify the issue (array of strings)
- "how_to_fix": exact fix with code/config/commands (array of strings)
- "references": relevant CVE/OWASP/CWE links (array of strings)
- "priority": fix priority 1-5 (1=fix immediately, 5=low priority)

Return ONLY a JSON array. No markdown."""


def generate_action_report(findings: list) -> list:
    """
    findings list leke Groq se action plan generate karo.
    Returns list of action items, ya [] agar fail ho.
    """
    if not findings:
        return []

    try:
        from groq import Groq
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            logger.warning("GROQ_API_KEY not set — action report skipped")
            return _fallback_action_report(findings)

        client = Groq(api_key=api_key)

        # Sirf relevant fields bhejo — token limit bachao
        slim_findings = []
        for f in findings[:20]:  # max 20 findings
            slim_findings.append({
                "title": f.get("title") or f.get("issue") or f.get("name") or f.get("type") or "Unknown Finding",
                "severity": f.get("severity", "MEDIUM"),
                "type": f.get("type", ""),
                "detail": str(f.get("detail", f.get("evidence", f.get("url", ""))))[:300],
            })

        prompt = USER_PROMPT_TEMPLATE.format(
            findings_json=json.dumps(slim_findings, indent=2)
        )

        for model in [GROQ_MODEL, FALLBACK_MODEL]:
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=4096,
                )
                raw = resp.choices[0].message.content.strip()
                # JSON parse karo
                action_items = json.loads(raw)
                if isinstance(action_items, list):
                    return action_items
            except json.JSONDecodeError:
                # Try to extract JSON array from response
                import re
                match = re.search(r'\[.*\]', raw, re.DOTALL)
                if match:
                    try:
                        return json.loads(match.group())
                    except Exception:
                        pass
            except Exception as e:
                logger.warning(f"Groq model {model} failed: {e}")
                continue

        return _fallback_action_report(findings)

    except ImportError:
        logger.warning("groq package not installed — using fallback")
        return _fallback_action_report(findings)
    except Exception as e:
        logger.error(f"Action report generation failed: {e}")
        return _fallback_action_report(findings)


def _fallback_action_report(findings: list) -> list:
    """Groq na ho to basic action items generate karo."""
    SEVERITY_PRIORITY = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

    GENERIC_FIXES = {
        "sqli": {
            "what_it_is": "SQL Injection allows attackers to manipulate database queries by injecting malicious SQL code through user input.",
            "how_to_fix": ["Use parameterized queries / prepared statements", "Implement input validation and sanitization", "Apply principle of least privilege on DB accounts"],
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
        },
        "xss": {
            "what_it_is": "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.",
            "how_to_fix": ["Encode all user-supplied output (HTML entity encoding)", "Implement Content Security Policy (CSP) headers", "Use modern frameworks with built-in XSS protection"],
            "references": ["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
        },
        "ssl": {
            "what_it_is": "Weak SSL/TLS configuration exposes encrypted traffic to interception or downgrade attacks.",
            "how_to_fix": ["Upgrade to TLS 1.2/1.3 only, disable SSLv3/TLS 1.0/1.1", "Use strong cipher suites (AES-256-GCM, CHACHA20)", "Renew certificate before expiry"],
            "references": ["https://owasp.org/www-project-transport-layer-protection-cheat-sheet/"],
        },
        "cors": {
            "what_it_is": "CORS misconfiguration allows unauthorized origins to make cross-origin requests to your API.",
            "how_to_fix": ["Whitelist only trusted origins explicitly", "Never use wildcard (*) with credentials", "Validate Origin header server-side"],
            "references": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        },
        "breach": {
            "what_it_is": "Credentials or PII found in public data breaches — attackers can use these for credential stuffing attacks.",
            "how_to_fix": ["Force password reset for affected accounts immediately", "Enable multi-factor authentication (MFA)", "Monitor for credential stuffing attempts in logs"],
            "references": ["https://haveibeenpwned.com/", "https://owasp.org/www-community/attacks/Credential_stuffing"],
        },
    }

    results = []
    for f in findings:
        title = f.get("title") or f.get("issue") or f.get("name") or f.get("type") or "Unknown Finding"
        severity = f.get("severity", "MEDIUM")
        ftype = f.get("type", "").lower()

        # Type se generic fix dhundho
        fix_data = {}
        for key, data in GENERIC_FIXES.items():
            if key in ftype or key in title.lower():
                fix_data = data
                break

        results.append({
            "title": title,
            "severity": severity,
            "what_it_is": fix_data.get("what_it_is", f"Security issue detected: {title}. Review the finding details and apply appropriate security controls."),
            "how_to_reproduce": ["Review the scan report for exact URL/parameter", "Use the provided evidence to verify the issue manually"],
            "how_to_fix": fix_data.get("how_to_fix", ["Review security best practices for this finding type", "Consult OWASP guidelines", "Apply vendor security patches if applicable"]),
            "references": fix_data.get("references", ["https://owasp.org/", "https://cwe.mitre.org/"]),
            "priority": SEVERITY_PRIORITY.get(severity.upper(), 3),
        })

    # Priority ke hisaab se sort karo
    results.sort(key=lambda x: x["priority"])
    return results


def render_action_report_html(action_items: list) -> str:
    """Action items ko HTML section mein convert karo."""
    if not action_items:
        return ""

    PRIORITY_LABELS = {1: "🔴 Fix Immediately", 2: "🟠 Fix This Week", 3: "🟡 Fix This Month", 4: "🟢 Low Priority", 5: "⚪ Informational"}
    SEV_COLORS = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f39c12", "LOW": "#27ae60", "INFO": "#58a6ff"}

    html = """
<div class="action-report-section">
  <h2 style="color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:8px;margin-top:40px;">
    🎯 AI Action Plan — How To Fix
  </h2>
  <p style="color:#aaa;margin-bottom:24px;">
    AI-generated remediation guide. Each finding includes what it is, how to reproduce, and exact fix steps.
  </p>
"""

    for i, item in enumerate(action_items, 1):
        sev = item.get("severity", "MEDIUM").upper()
        sev_color = SEV_COLORS.get(sev, "#f39c12")
        priority = item.get("priority", 3)
        priority_label = PRIORITY_LABELS.get(priority, "")

        how_to_reproduce = item.get("how_to_reproduce", [])
        how_to_fix = item.get("how_to_fix", [])
        references = item.get("references", [])

        reproduce_html = "".join(f"<li>{step}</li>" for step in how_to_reproduce)
        fix_html = "".join(f"<li><code style='background:#1a1a2e;padding:2px 6px;border-radius:3px;color:#00d4ff'>{step}</code></li>" for step in how_to_fix)
        ref_html = "".join(f'<li><a href="{ref}" target="_blank" style="color:#00d4ff">{ref}</a></li>' for ref in references)

        html += f"""
  <div style="background:#0d1117;border:1px solid #30363d;border-left:4px solid {sev_color};border-radius:8px;padding:20px;margin-bottom:20px;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <h3 style="color:#fff;margin:0;font-size:16px;">#{i} {item.get('title','')}</h3>
      <div>
        <span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;">{sev}</span>
        <span style="color:#aaa;font-size:12px;margin-left:10px;">{priority_label}</span>
      </div>
    </div>

    <div style="margin-bottom:14px;">
      <strong style="color:#00d4ff;">📋 What Is This?</strong>
      <p style="color:#ccc;margin:6px 0 0 0;">{item.get('what_it_is','')}</p>
    </div>

    <div style="margin-bottom:14px;">
      <strong style="color:#f39c12;">🔍 How To Reproduce / Verify:</strong>
      <ol style="color:#ccc;margin:6px 0 0 16px;">{reproduce_html}</ol>
    </div>

    <div style="margin-bottom:14px;">
      <strong style="color:#27ae60;">🔧 How To Fix:</strong>
      <ol style="color:#ccc;margin:6px 0 0 16px;">{fix_html}</ol>
    </div>

    {"<div><strong style='color:#aaa;'>📚 References:</strong><ul style='color:#aaa;margin:6px 0 0 16px;'>" + ref_html + "</ul></div>" if references else ""}
  </div>
"""

    html += "</div>"
    return html
