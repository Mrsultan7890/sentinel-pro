"""
LinkedIn / Job Posting OSINT
Extracts tech stack intelligence from job postings:
- LinkedIn job search (public, no auth)
- Indeed / Glassdoor via Google dorking
- GitHub Jobs / Greenhouse / Lever / Workday
- Extracts: languages, frameworks, databases, cloud, tools, security stack
"""

import re
import logging
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

# Tech keyword categories to extract from job descriptions
TECH_PATTERNS = {
    'Languages':    r'\b(Python|Java|Go|Golang|Rust|Ruby|PHP|C\+\+|C#|TypeScript|JavaScript|Kotlin|Swift|Scala|Perl|Elixir)\b',
    'Frameworks':   r'\b(Django|Flask|FastAPI|Spring|Rails|Laravel|Express|Next\.js|React|Angular|Vue|Svelte|ASP\.NET|Gin|Fiber)\b',
    'Databases':    r'\b(PostgreSQL|MySQL|MongoDB|Redis|Elasticsearch|Cassandra|DynamoDB|SQLite|Oracle|MSSQL|ClickHouse|Snowflake|BigQuery)\b',
    'Cloud':        r'\b(AWS|Azure|GCP|Google Cloud|Kubernetes|K8s|Docker|Terraform|Ansible|Helm|EKS|ECS|Lambda|S3|EC2|GKE|AKS)\b',
    'Security':     r'\b(SIEM|SOC|WAF|IDS|IPS|Splunk|CrowdStrike|Okta|SAML|OAuth|JWT|LDAP|Active Directory|Vault|HSM|SAST|DAST|Burp Suite|Nessus)\b',
    'CI/CD':        r'\b(Jenkins|GitLab CI|GitHub Actions|CircleCI|Travis|ArgoCD|Spinnaker|TeamCity|Bamboo|Drone)\b',
    'Monitoring':   r'\b(Datadog|Grafana|Prometheus|New Relic|Dynatrace|PagerDuty|Kibana|Logstash|Jaeger|Zipkin)\b',
    'Message Queue':r'\b(Kafka|RabbitMQ|SQS|Celery|NATS|Pulsar|ActiveMQ|ZeroMQ)\b',
    'OS/Infra':     r'\b(Linux|Ubuntu|CentOS|RHEL|Debian|Nginx|Apache|HAProxy|Istio|Envoy|Consul)\b',
}

# Job board URL patterns
JOB_SOURCES = [
    # LinkedIn public job search
    'https://www.linkedin.com/jobs/search/?keywords={company}&location=&f_TPR=r604800',
    # Greenhouse
    'https://boards.greenhouse.io/{slug}',
    # Lever
    'https://jobs.lever.co/{slug}',
    # Workday
    'https://{slug}.wd1.myworkdayjobs.com/en-US/External',
    # Google dork for job postings
    'https://www.google.com/search?q=site:linkedin.com/jobs+"{company}"+engineer',
    'https://www.google.com/search?q="{company}"+jobs+site:greenhouse.io+OR+site:lever.co',
]

# Slug candidates from domain
def _slugs(domain: str) -> list:
    parts = domain.lower().split('.')
    parts = [p for p in parts if p not in ('www', 'com', 'net', 'org', 'io', 'co')]
    slugs = []
    for p in parts:
        slugs.append(p)
        slugs.extend(p.split('-'))
    return list(dict.fromkeys(s for s in slugs if len(s) >= 3))


class JobOSINT:

    def run(self, domain: str) -> dict:
        result = {
            'domain':       domain,
            'jobs_found':   [],
            'tech_stack':   {},
            'raw_mentions': {},
            'risk_flags':   [],
            'total_jobs':   0,
            'error':        None,
        }

        company = domain.split('.')[0]
        slugs   = _slugs(domain)
        all_text = []

        # ── 1. Greenhouse ─────────────────────────────────────────────────────
        for slug in slugs[:3]:
            r = rate_limited_get(
                f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true",
                namespace='jobs', timeout=6
            )
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    jobs = data.get('jobs', [])
                    for job in jobs[:20]:
                        title   = job.get('title', '')
                        content = job.get('content', '')
                        loc     = job.get('location', {}).get('name', '')
                        result['jobs_found'].append({
                            'source': 'Greenhouse',
                            'title':  title,
                            'location': loc,
                            'url':    job.get('absolute_url', ''),
                        })
                        all_text.append(f"{title} {content}")
                    if jobs:
                        break
                except Exception:
                    pass

        # ── 2. Lever ──────────────────────────────────────────────────────────
        for slug in slugs[:3]:
            r = rate_limited_get(
                f"https://api.lever.co/v0/postings/{slug}?mode=json",
                namespace='jobs', timeout=6
            )
            if r and r.status_code == 200:
                try:
                    jobs = r.json()
                    if isinstance(jobs, list):
                        for job in jobs[:20]:
                            title = job.get('text', '')
                            desc  = ' '.join(
                                l.get('content', '') for l in job.get('descriptionBody', {}).get('content', [])
                                if isinstance(l, dict)
                            )
                            result['jobs_found'].append({
                                'source': 'Lever',
                                'title':  title,
                                'location': job.get('categories', {}).get('location', ''),
                                'url':    job.get('hostedUrl', ''),
                            })
                            all_text.append(f"{title} {desc}")
                        if jobs:
                            break
                except Exception:
                    pass

        # ── 3. LinkedIn public (no auth, limited) ─────────────────────────────
        r = rate_limited_get(
            f"https://www.linkedin.com/jobs/search/?keywords={company}&f_TPR=r2592000",
            namespace='jobs', timeout=6,
            headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
        )
        if r and r.status_code == 200:
            # Extract job titles from HTML
            titles = re.findall(
                r'class="base-search-card__title"[^>]*>\s*([^<]{5,80})',
                r.text
            )
            for t in titles[:15]:
                result['jobs_found'].append({
                    'source': 'LinkedIn',
                    'title':  t.strip(),
                    'location': '',
                    'url':    f"https://www.linkedin.com/jobs/search/?keywords={company}",
                })
            all_text.append(r.text[:30000])

        # ── 4. Indeed via scrape ──────────────────────────────────────────────
        r = rate_limited_get(
            f"https://www.indeed.com/jobs?q={company}+engineer&l=",
            namespace='jobs', timeout=6,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        if r and r.status_code == 200:
            all_text.append(r.text[:20000])

        # ── 5. Extract tech stack from all collected text ─────────────────────
        combined = ' '.join(all_text)
        for category, pattern in TECH_PATTERNS.items():
            matches = re.findall(pattern, combined, re.IGNORECASE)
            if matches:
                # Normalize case and deduplicate
                unique = list(dict.fromkeys(m.strip() for m in matches))
                result['tech_stack'][category] = unique
                result['raw_mentions'][category] = len(matches)

        result['total_jobs'] = len(result['jobs_found'])

        # ── 6. Validate — hosting provider ka data filter karo ───────────────
        # Netlify, Render, Vercel, GitHub Pages ke jobs actual site ke nahi hain
        HOSTING_PROVIDERS = {
            'netlify.app':   'Netlify',
            'render.com':    'Render',
            'vercel.app':    'Vercel',
            'github.io':     'GitHub Pages',
            'pages.dev':     'Cloudflare Pages',
            'herokuapp.com': 'Heroku',
            'azurewebsites.net': 'Azure',
            'appspot.com':   'Google App Engine',
            'amplifyapp.com': 'AWS Amplify',
        }

        provider = None
        for suffix, name in HOSTING_PROVIDERS.items():
            if domain.endswith(suffix):
                provider = name
                break

        if provider:
            # Hosting provider pe hosted site hai — job data unreliable
            result['jobs_found']  = []
            result['tech_stack']  = {}
            result['raw_mentions'] = {}
            result['total_jobs']  = 0
            result['error'] = (
                f'Site is hosted on {provider} — job postings would reflect '
                f'{provider} company, not the actual site owner. Tech stack detection skipped.'
            )
            result['hosting_provider'] = provider
            logger.info(f"[JobOSINT] {domain} is on {provider} — skipping job data")
            return result

        # ── 7. Risk flags ─────────────────────────────────────────────────────
        sec_stack = result['tech_stack'].get('Security', [])
        if sec_stack:
            result['risk_flags'].append({
                'severity': 'INFO',
                'flag': 'Security Stack Leaked',
                'detail': f"Job ads mention: {', '.join(sec_stack[:8])}",
            })

        cloud_stack = result['tech_stack'].get('Cloud', [])
        if cloud_stack:
            result['risk_flags'].append({
                'severity': 'INFO',
                'flag': 'Cloud Stack Identified',
                'detail': f"Cloud tech: {', '.join(cloud_stack[:8])}",
            })

        db_stack = result['tech_stack'].get('Databases', [])
        if db_stack:
            result['risk_flags'].append({
                'severity': 'INFO',
                'flag': 'Database Stack Identified',
                'detail': f"Databases: {', '.join(db_stack[:6])}",
            })

        if result['total_jobs'] == 0:
            result['error'] = 'No job postings found (company may use different slug)'

        return result
