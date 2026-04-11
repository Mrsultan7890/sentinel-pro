# The Sentinel Pro — Issues Registry

> Poore codebase ka manual review karke nikale gaye issues.
> Status: [ ] = pending, [x] = fixed

---

## 🔴 P1 — Critical (Crash / Data Loss)

### [P1-01] `lfi_scanner.py` — Duplicate class definition
- **File:** `modules/bugbounty/lfi_scanner.py`
- **Problem:** `LFIScanner` class **do baar** define hai. `LFI_PARAMS`, `LFI_PAYLOADS`, `LFI_SIGNATURES`, `RFI_PAYLOADS` constants bhi duplicate hain. Python silently dusri (inferior) definition use karta hai — pehli optimized class (jo `MAX_WORKERS`, `FAST_PAYLOADS`, `TIMEOUT` use karti hai) completely ignore ho jaati hai.
- **Impact:** Scanner slow chalega, fast payloads use nahi honge, parallel execution nahi hogi.
- **Fix:** Dusri duplicate class aur duplicate constants delete karo (line ~100 ke baad sab).
- **Status:** [x] FIXED

---

### [P1-02] `ssti_scanner.py` — Duplicate class definition
- **File:** `modules/bugbounty/ssti_scanner.py`
- **Problem:** `SSTIScanner` class **do baar** define hai. `SSTI_PROBES` aur `SSTI_PARAMS` bhi duplicate hain. Pehli class mein `MAX_WORKERS=20`, `MAX_TARGETS=5`, `MAX_PARAMS=8` constants hain aur `ThreadPoolExecutor` use hota hai. Dusri class mein yeh sab nahi — sequential loop hai. Python dusri definition use karta hai.
- **Impact:** SSTI scanner slow chalega, parallel execution nahi hogi, aur extended SSTI_PROBES (Freemarker RCE, Smarty math) use nahi honge.
- **Fix:** Dusri duplicate class aur duplicate constants delete karo.
- **Status:** [x] FIXED

---

### [P1-03] `prototype_pollution.py` — `_check_response` method missing
- **File:** `modules/bugbounty/prototype_pollution.py`
- **Problem:** `_probe` method line pe `return self._check_response(r.text, url, method, payload_str)` call karta hai lekin `PrototypePollutionScanner` class mein `_check_response` method define hi nahi hai.
- **Impact:** Prototype pollution scanner chalate hi `AttributeError: 'PrototypePollutionScanner' object has no attribute '_check_response'` crash dega.
- **Fix:** `_check_response(self, text, url, method, payload_str)` method implement karo jo `PP_SIGNATURES` patterns check kare.
- **Status:** [x] FIXED

---

### [P1-04] `main.py` — `report_data['subdomains']` KeyError
- **File:** `main.py`, method `_handle_bugbounty`, line ~680
- **Problem:**
  ```python
  subs = report_data['subdomains'].get('subdomains', []) if 'subdomains' in report_data else []
  ```
  `report_data['subdomains']` kabhi set nahi hota `_handle_bugbounty` flow mein — yeh sirf `_handle_recon` mein set hota hai. Condition `'subdomains' in report_data` False hogi toh `[]` milega — yeh theek hai. Lekin agar koi future change kare toh fragile hai. Actual bug: `sub_list` empty hone par `self.takeover.run(target, sub_list or None)` mein `None` pass hota hai jo `SubdomainTakeover._get_subdomains` fallback trigger karta hai — yeh intentional nahi lagta.
- **Impact:** Subdomain takeover check sirf common 20 subdomains pe hoga, actual enumerated subdomains pe nahi.
- **Fix:** Bugbounty scan mein bhi subdomain enumeration run karo ya clearly document karo ki takeover check limited hai.
- **Status:** [x] FIXED

---

### [P1-05] `ssl_checker.py` — `domain` NameError in `_parse_cert_binary`
- **File:** `modules/bugbounty/ssl_checker.py`, method `_parse_cert_binary`
- **Problem:**
  ```python
  subject_cn = domain if hasattr(self, '_current_domain') else ''
  ```
  `domain` variable `_parse_cert_binary` ke scope mein exist nahi karta — yeh parameter nahi hai is method ka. `_current_domain` attribute bhi kabhi set nahi hota.
- **Impact:** `CERT_NONE` mode mein (self-signed certs ke liye) `NameError: name 'domain' is not defined` crash dega.
- **Fix:** `domain` parameter `_parse_cert_binary` mein pass karo ya `''` use karo directly.
- **Status:** [x] FIXED

---

### [P1-06] `auth_bypass.py` — Duplicate import
- **File:** `modules/bugbounty/auth_bypass.py`, lines 11-12
- **Problem:**
  ```python
  from modules.utils import tor_session                    # line 11
  from modules.utils import rate_limited_get, tor_session  # line 12
  ```
  `tor_session` do baar import ho raha hai. `rate_limited_get` import hota hai lekin file mein kabhi use nahi hota.
- **Impact:** Unused import — code quality issue, potential confusion.
- **Fix:** Line 11 delete karo, line 12 se `rate_limited_get` bhi hata do (unused).
- **Status:** [x] FIXED

---

## 🟡 P2 — High (Logic Bugs / Wrong Behavior)

### [P2-01] `utils.py` — Thread-unsafe rate limiter
- **File:** `modules/utils.py`
- **Problem:**
  ```python
  _last_call: dict[str, float] = {}  # global dict, no lock
  ```
  `rate_limited_get` multiple threads se simultaneously call hota hai (ThreadPoolExecutor in vuln_scanner, endpoint_scanner, etc.) lekin `_last_call` dict bina `threading.Lock()` ke access hota hai — race condition possible.
- **Impact:** Rate limiting bypass ho sakta hai, ya dict corruption se crash.
- **Fix:** `threading.Lock()` add karo `_last_call` access ke around.
- **Status:** [x] FIXED

---

### [P2-02] `subdomain_takeover.py` — False positive on unreachable hosts
- **File:** `modules/bugbounty/subdomain_takeover.py`, method `_check`
- **Problem:**
  ```python
  else:
      # No response = CNAME exists but host unreachable = likely vulnerable
      vulnerable = True
      evidence = f'CNAME → {cname} | Host unreachable (dangling DNS)'
  ```
  `rate_limited_get` `None` return karta hai network timeout, connection error, DNS failure — sab cases mein. Yeh sab "vulnerable" mark ho jaate hain.
- **Impact:** Bahut zyada false positives — har unreachable host CRITICAL vulnerability ban jaata hai.
- **Fix:** `None` response ko alag handle karo — sirf tab vulnerable mark karo jab response mile aur fingerprint string match kare. Unreachable = "unverified/possible" mark karo.
- **Status:** [x] FIXED

---

### [P2-03] `writing_fingerprinter.py` — Thread-unsafe shared vectorizer
- **File:** `modules/ml_engine/writing_fingerprinter.py`
- **Problem:**
  ```python
  self.char_vectorizer = TfidfVectorizer(...)  # instance variable
  self.word_vectorizer = TfidfVectorizer(...)

  def compare(self, text_a, text_b):
      matrix = self.char_vectorizer.fit_transform([text_a, text_b])  # shared state modify
  ```
  `compare()` har call pe shared instance vectorizers pe `fit_transform` karta hai. Concurrent calls mein vectorizer state corrupt ho sakta hai.
- **Impact:** Concurrent NLP analysis mein wrong results ya crash.
- **Fix:** `compare()` mein local vectorizer instances banao instead of using `self.char_vectorizer`.
- **Status:** [x] FIXED

---

### [P2-04] `api_scanner.py` — `import json` unused + `METHODS_TO_TEST` unused
- **File:** `modules/bugbounty/api_scanner.py`
- **Problem:**
  - Line 9: `import json` — file mein kabhi use nahi hota.
  - Line 55: `METHODS_TO_TEST = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']` define hai lekin `_test_methods` mein hardcoded `dangerous` dict use hota hai, yeh list ignore hoti hai.
- **Impact:** Dead code / confusion.
- **Fix:** `import json` remove karo. `_test_methods` mein `METHODS_TO_TEST` use karo ya list remove karo.
- **Status:** [x] FIXED

---

### [P2-05] `api_scanner.py` — Mass assignment false positives
- **File:** `modules/bugbounty/api_scanner.py`, method `_test_mass_assignment`
- **Problem:**
  ```python
  if r.status_code in (200, 201):
      body = r.text.lower()
      if 'admin' in body or 'role' in body:
          # CRITICAL: Mass Assignment
  ```
  Koi bhi page jo "admin" ya "role" word contain kare (navigation menu, footer, etc.) CRITICAL mark ho jaayega.
- **Impact:** Massive false positives — almost every site CRITICAL mass assignment vulnerability dikhayega.
- **Fix:** Response body mein specifically `"role":"admin"` ya `"is_admin":true` JSON pattern check karo, generic word match nahi.
- **Status:** [x] FIXED

---

### [P2-06] `vuln_scanner.py` — Blind SQLi timeout = false positive
- **File:** `modules/bugbounty/vuln_scanner.py`, method `_test_sqli_blind`
- **Problem:**
  ```python
  except requests.Timeout:
      findings.append({
          'type': 'Blind SQLi',
          'evidence': f"{label}: request timed out (possible sleep injection)",
          'severity': 'CRITICAL',
      })
  ```
  Network timeout, server overload, ya slow connection bhi `requests.Timeout` raise karta hai — yeh sab Blind SQLi mark ho jaate hain.
- **Impact:** False positives — slow servers CRITICAL SQLi vulnerability dikhate hain.
- **Fix:** Timeout ko "possible" ya "MEDIUM" mark karo, ya baseline timeout se compare karo pehle.
- **Status:** [x] FIXED

---

### [P2-07] `cloud_assets.py` — `PERMUTATIONS` list duplicate
- **File:** `modules/recon/cloud_assets.py`
- **Problem:** `PERMUTATIONS` list file ke top pe define hai (line ~15) aur file ke end mein dobara define hai (line ~180+). `S3_REGIONS` list bhi end mein define hai lekin kabhi use nahi hoti.
- **Impact:** Dead code, memory waste, confusion.
- **Fix:** Duplicate `PERMUTATIONS` aur unused `S3_REGIONS` delete karo.
- **Status:** [x] FIXED

---

### [P2-08] `asn_mapper.py` — `_fetch_org_asns` empty return (dead code)
- **File:** `modules/recon/asn_mapper.py`, method `_fetch_org_asns`
- **Problem:**
  ```python
  def _fetch_org_asns(self, asn_id: str, org_name: str) -> list:
      # ...
      for peer in data.get('rir_allocation', {}).get('rir_name', ''):
          pass  # placeholder — bgpview doesn't expose sibling ASNs directly
      return related  # always []
  ```
  Method hamesha empty list return karta hai — loop body mein sirf `pass` hai.
- **Impact:** `org_asns` feature kaam nahi karta, silently.
- **Fix:** Ya implement karo (bgpview `/asn/{num}/upstreams` endpoint use karo) ya method remove karo aur call site se bhi hata do.
- **Status:** [x] FIXED

---

### [P2-09] `cookie_analyzer.py` — `httponly` detection unreliable
- **File:** `modules/bugbounty/cookie_analyzer.py`
- **Problem:**
  ```python
  httponly = 'httponly' in str(c._rest).lower() if hasattr(c, '_rest') else False
  ```
  `requests.cookies.RequestsCookieJar` mein `_rest` private attribute hai — requests library version change hone par break ho sakta hai. Dono code paths (requests cookie object vs parsed dict) inconsistent hain.
- **Impact:** HttpOnly flag detection miss ho sakta hai — false negatives.
- **Fix:** `Set-Cookie` header directly parse karo `_parse_set_cookie` se (jo already exist karta hai) — dono paths consistent karo.
- **Status:** [x] FIXED

---

### [P2-10] `wayback.py` — `limit: 1000` vs README `5000 URLs`
- **File:** `modules/recon/wayback.py`
- **Problem:**
  ```python
  'limit': 1000,
  ```
  README mein "Wayback Machine (5000 URLs)" likha hai lekin code mein `limit: 1000` hai.
- **Impact:** README misleading hai — user 5000 URLs expect karta hai, 1000 milte hain.
- **Fix:** `limit` ko `5000` karo ya README update karo.
- **Status:** [x] FIXED

---

### [P2-11] `phone_osint.py` — HTTP instead of HTTPS for NumVerify API
- **File:** `modules/recon/phone_osint.py`, method `_numverify_lookup`
- **Problem:**
  ```python
  resp = rate_limited_get('http://apilayer.net/api/validate', ...)
  ```
  API call HTTP pe ho rahi hai — API key plaintext travel karta hai.
- **Impact:** API key network sniffing se leak ho sakta hai.
- **Fix:** `http://` ko `https://` se replace karo.
- **Status:** [x] FIXED

---

### [P2-12] `email_osint.py` — Only 3 social platforms
- **File:** `modules/recon/email_osint.py`
- **Problem:**
  ```python
  SOCIAL_PATTERNS = {
      'github':    (...),
      'instagram': (...),
      'twitter':   (...),
  }
  ```
  Sirf 3 platforms check hote hain jabki `phone_osint.py` mein bhi limited hai. `collect` command 40+ platforms check karta hai lekin email OSINT mein sirf 3.
- **Impact:** Email OSINT incomplete — bahut kam social presence detection.
- **Fix:** LinkedIn, Reddit, TikTok, YouTube, Pinterest etc. add karo.
- **Status:** [x] FIXED

---

## 🟠 P3 — Medium (Security / Quality)

### [P3-01] `breach_checker.py` — Google scraping unreliable
- **File:** `modules/breach/breach_checker.py`, method `_check_pastes`
- **Problem:**
  ```python
  resp = self.session.get('https://www.google.com/search', params={'q': f'site:pastebin.com "{target}"'})
  ```
  Google bot detection se 429/CAPTCHA milega regularly. Yeh source unreliable hai.
- **Impact:** Paste monitoring feature mostly kaam nahi karega — silently fail hoga.
- **Fix:** Google scraping hata do. Sirf `psbdmp.ws` use karo ya `pastes.io` API add karo.
- **Status:** [x] FIXED

---

### [P3-02] `auth_bypass.py` — Default creds false positives
- **File:** `modules/bugbounty/auth_bypass.py`, method `_try_default_creds`
- **Problem:**
  ```python
  failed_keywords = ('invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied', 'unauthorized')
  if r.status_code in (200, 302) and not any(k in body_l for k in failed_keywords):
      if r.status_code == 302 or 'logout' in body_l or 'dashboard' in body_l:
          return {'username': user, 'password': pwd, ...}
  ```
  Koi bhi page jo redirect kare ya "dashboard" word contain kare (e.g., marketing page) "bypass successful" mark ho jaayega.
- **Impact:** False positives — non-login pages CRITICAL default credentials vulnerability dikhate hain.
- **Fix:** Stricter heuristics — login page URL se redirect location compare karo, ya response URL change check karo.
- **Status:** [x] FIXED

---

### [P3-03] `tech_fingerprint.py` — `mmh3` missing silent failure
- **File:** `modules/bugbounty/tech_fingerprint.py`
- **Problem:**
  ```python
  try:
      import mmh3, base64
      fav_hash = str(mmh3.hash(...))
  except Exception:
      pass  # silently ignored
  ```
  `mmh3` install nahi hone par favicon hash feature silently skip ho jaata hai — user ko pata nahi chalta.
- **Impact:** Favicon-based tech detection (Fortinet, Cisco, Jenkins, etc.) kaam nahi karta bina warning ke.
- **Fix:** `requirements.txt` mein `mmh3` add karo. Ya `except ImportError` mein `logger.debug` add karo.
- **Status:** [x] FIXED

---

### [P3-04] `main.py` — Bugbounty progress `advance` values 100 se zyada
- **File:** `main.py`, method `_handle_bugbounty`
- **Problem:** Progress bar ke saare `advance` values add karo — 200+ ho jaate hain. Rich library internally cap karta hai lekin yeh confusing hai aur progress bar accurately nahi dikhta.
- **Impact:** Progress bar misleading — 100% se pehle hi complete dikhta hai.
- **Fix:** Saare `advance` values recalculate karo taaki total = 100 ho.
- **Status:** [x] FIXED

---

### [P3-05] `config.py` — `validate_ml_engine` NLTK path logic
- **File:** `config.py`, method `validate_ml_engine`
- **Problem:**
  ```python
  nltk.data.find(f'tokenizers/{pkg}' if 'punkt' in pkg else
                 f'corpora/{pkg}' if pkg in ('stopwords','words') else
                 f'taggers/{pkg}' if 'tagger' in pkg else
                 f'chunkers/{pkg}')
  ```
  `maxent_ne_chunker_tab` ke liye `chunkers/maxent_ne_chunker_tab` check karta hai — yeh correct hai. Lekin `punkt_tab` ke liye `tokenizers/punkt_tab` check karta hai — NLTK actually ise `tokenizers/punkt_tab` mein store karta hai, toh yeh bhi correct hai. Minor issue: `averaged_perceptron_tagger_eng` ke liye path `taggers/averaged_perceptron_tagger_eng` hona chahiye jo sahi hai.
- **Impact:** Status check mein minor inaccuracy possible.
- **Fix:** Har package ke liye explicit path mapping use karo instead of conditional logic.
- **Status:** [x] FIXED

---

### [P3-06] `endpoint_scanner.py` — Cloud metadata paths misleading
- **File:** `modules/bugbounty/endpoint_scanner.py`, `SENSITIVE_PATHS` list
- **Problem:**
  ```python
  '/latest/meta-data/',
  '/computeMetadata/v1/',
  '/metadata/instance',
  ```
  Yeh paths external web servers pe scan karne se kuch nahi milega — yeh sirf AWS/GCP instance ke localhost pe accessible hote hain (169.254.169.254). External domain pe yeh paths 404 denge.
- **Impact:** False sense of security — user sochta hai cloud metadata check ho raha hai jabki nahi.
- **Fix:** Yeh paths `SENSITIVE_PATHS` se hata do. Cloud metadata check SSRF scanner mein already properly handle hota hai.
- **Status:** [x] FIXED

---

### [P3-07] `nlp_analyzer.py` — `sent_tokenize` without try/except
- **File:** `modules/ml_engine/nlp_analyzer.py`, method `_analyze_writing_style`
- **Problem:**
  ```python
  sentences = sent_tokenize(combined) if combined else []
  ```
  `sent_tokenize` NLTK `punkt` data pe dependent hai. Agar data missing ho toh `LookupError` raise hoga — yahan koi `try/except` nahi hai.
- **Impact:** Writing style analysis crash kar sakta hai agar NLTK data properly install nahi hua.
- **Fix:** `try/except LookupError` wrap karo, fallback: `combined.split('.')`.
- **Status:** [x] FIXED

---

### [P3-08] `google_dorker.py` — Fallback behavior undocumented
- **File:** `modules/recon/google_dorker.py`
- **Problem:** Bina `SERPAPI_KEY` ke `_run_fallback` sirf Google search URLs return karta hai — actual results nahi. Yeh behavior README mein clearly mention nahi.
- **Impact:** User sochta hai Google dorking kaam kar raha hai jabki sirf manual URLs mil rahe hain.
- **Fix:** Output mein clearly indicate karo ki yeh manual dorks hain, actual results nahi. README update karo.
- **Status:** [x] FIXED

---

### [P3-09] `subdomain_enum.py` — DNS brute-force no rate limiting
- **File:** `modules/recon/subdomain_enum.py`, method `_dns_brute`
- **Problem:**
  ```python
  with ThreadPoolExecutor(max_workers=50) as ex:
      futures = {ex.submit(resolve, s): s for s in WORDLIST}
  ```
  50 threads directly `socket.gethostbyname` call karte hain bina kisi delay ke — DNS server ban kar sakta hai ya rate limit ho sakta hai.
- **Impact:** DNS queries drop ho sakti hain, false negatives (subdomains miss ho jaate hain).
- **Fix:** `max_workers` ko 20-30 tak reduce karo ya DNS resolver timeout properly set karo.
- **Status:** [x] FIXED

---

### [P3-10] `breach_checker.py` — Session reuse after Tor toggle
- **File:** `modules/breach/breach_checker.py`
- **Problem:**
  ```python
  def __init__(self):
      self.session = tor_session()  # session __init__ mein banta hai
  ```
  Agar user `tor on` command de `BreachChecker` instantiate hone ke baad, toh purana session (bina Tor ke) use hota rahega.
- **Impact:** Tor enable karne ke baad bhi breach checks direct connection se hote hain.
- **Fix:** `run()` method mein fresh session banao, ya `tor_session()` ko lazy evaluate karo.
- **Status:** [x] FIXED

---

## 🟢 P4 — Low (Minor / Improvements)

### [P4-01] `api_scanner.py` — Only HTTPS tested
- **File:** `modules/bugbounty/api_scanner.py`
- **Problem:** `base = f"https://{domain}"` — sirf HTTPS check hota hai. Kuch APIs sirf HTTP pe hote hain.
- **Fix:** HTTP fallback add karo agar HTTPS fail ho.
- **Status:** [x] FIXED

---

### [P4-02] `api_scanner.py` — IDOR check sirf `/api/v1/` prefix
- **File:** `modules/bugbounty/api_scanner.py`, method `_probe_idor`
- **Problem:** IDOR paths hardcoded `/api/v1/` prefix ke saath hain. Real apps mein `/api/v2/`, `/v1/`, `/rest/` bhi hote hain.
- **Fix:** `endpoints_found` se discovered paths use karo IDOR probing ke liye.
- **Status:** [x] FIXED

---

### [P4-03] `cve_lookup.py` — Missing module docstring
- **File:** `modules/bugbounty/cve_lookup.py`
- **Problem:** File mein module-level docstring nahi hai (baaki sab files mein hai).
- **Fix:** Docstring add karo.
- **Status:** [x] FIXED

---

### [P4-04] `main.py` — `_handle_bugbounty` mein `report_data['subdomains']` reference
- **File:** `main.py`
- **Problem:** `report_data` dict mein `subdomains` key set nahi hoti bugbounty flow mein, lekin code `'subdomains' in report_data` check karta hai — yeh always False hoga. Confusing code.
- **Fix:** Comment add karo ya clearly `sub_list = []` set karo with explanation.
- **Status:** [x] FIXED

---

### [P4-05] `requirements.txt` — `mmh3` missing
- **File:** `requirements.txt`
- **Problem:** `tech_fingerprint.py` mein `mmh3` import hota hai lekin `requirements.txt` mein listed nahi.
- **Fix:** `mmh3` add karo `requirements.txt` mein.
- **Status:** [x] FIXED

---

## 📊 Summary

| Priority | Count | Description |
|----------|-------|-------------|
| 🔴 P1 Critical | 6 | Crash / NameError / AttributeError |
| 🟡 P2 High | 12 | Logic bugs / wrong behavior |
| 🟠 P3 Medium | 10 | Security / quality issues |
| 🟢 P4 Low | 5 | Minor improvements |
| **Total** | **33** | |

---

## Fix Order (Recommended)

```
P1-03 → P1-01 → P1-02 → P1-05 → P1-06 → P1-04
P2-01 → P2-02 → P2-03 → P2-04 → P2-05 → P2-06
P2-07 → P2-08 → P2-09 → P2-10 → P2-11 → P2-12
P3-01 → P3-02 → P3-03 → P3-06 → P3-07 → P3-09 → P3-10
P4-05 → P4-01 → P4-02
```
