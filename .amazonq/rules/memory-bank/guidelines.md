# The Sentinel Pro v3.0 — Development Guidelines

## Code Quality Standards

### Python Conventions
- Module-level docstrings explain purpose, flow, and usage (seen in trainer.py, main.py)
- Class docstrings describe the component's role
- Method docstrings are concise — one line for simple methods, multi-line for complex ones
- Inline comments in Urdu/Hindi mixed with English are common (e.g., `# model ka brain`, `# Sirf command keyword lowercase karo`) — preserve this style when editing existing files
- Type hints used selectively on public method signatures, not universally enforced
- `logger = logging.getLogger(__name__)` at module level — always use module-level logger

### Go Conventions
- All exported types use JSON struct tags: `json:"field_name"`
- Constructor functions named `NewXxx()` returning pointer: `func NewNetworkMapper() *NetworkMapper`
- Helper functions at bottom of file (getString, getInt, getBool pattern)
- No external dependencies beyond stdlib — Go services are self-contained
- Output always via `fmt.Println(string(output))` to stdout as JSON

### Rust Conventions
- All data structures derive `Serialize, Deserialize, Debug`
- `main()` reads args, calls a primary function, prints JSON to stdout
- Error handling via `Result<T, Box<dyn std::error::Error>>`
- Parallel processing with `rayon::prelude::*` where applicable
- Helper functions are pure (no side effects), named descriptively

---

## Structural Conventions

### Python Module Structure
Every module follows this pattern:
```python
"""
Module docstring — purpose, flow, usage
"""
import ...
logger = logging.getLogger(__name__)

# Module-level constants (UPPER_SNAKE_CASE)
MODELS_DIR = Path(__file__).resolve().parents[2] / 'models' / 'ml_engine'

class ClassName:
    def __init__(self):
        ...
    
    def public_method(self):
        """One-line docstring."""
        ...
    
    def _private_method(self):
        ...
    
    @staticmethod
    def static_utility():
        ...
```

### Scan Result Return Format
All scanner modules return a consistent dict structure:
```python
{
    'target': str,
    'timestamp': datetime.now().isoformat(),
    'risk_level': 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    'total_<findings>': int,
    'findings': [...],
    'risk_flags': [{'flag': str, 'detail': str, 'severity': str}],
    'error': str | None,  # present only on failure
}
```

### Bridge Pattern (Python → Go/Rust)
```python
result = subprocess.run(
    [str(config.BINARY_BIN), arg1, arg2],
    capture_output=True,
    text=True,
    timeout=30,
    cwd=str(config.BASE_DIR)
)
if result.returncode == 0:
    data = json.loads(result.stdout)
else:
    return {'error': result.stderr}
```
- Always check `returncode == 0`
- Always handle `subprocess.TimeoutExpired` and `json.JSONDecodeError`
- Binary paths come from `config.py` constants

### Go Service Pattern
```go
func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: binary <arg>")
        os.Exit(1)
    }
    // Read input file or arg
    // Process
    output, _ := json.MarshalIndent(result, "", "  ")
    fmt.Println(string(output))
}
```
- Input via CLI args (file path or direct value)
- Output always JSON to stdout
- Errors to stderr via `log.Fatal()`

---

## Naming Conventions

### Python
- Classes: `PascalCase` (e.g., `ModelTrainer`, `SentinelBrain`, `EnhancedProfileExtractor`)
- Methods/functions: `snake_case`
- Private methods: `_snake_case` prefix
- Constants: `UPPER_SNAKE_CASE`
- Module files: `snake_case.py`
- Handler methods in main class: `_handle_<command>()` pattern

### Go
- Types/structs: `PascalCase` with JSON tags
- Functions: `camelCase` for unexported, `PascalCase` for exported
- Receiver methods: short lowercase receiver name (e.g., `nm` for `NetworkMapper`)

### Rust
- Structs: `PascalCase`
- Functions: `snake_case`
- Constants: `UPPER_SNAKE_CASE`

---

## Architectural Patterns

### Threat Level Enum
Used consistently across all languages:
- `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`
- Color mapping: green → yellow → orange/red → red
- Rich markup: `[green]LOW[/green]`, `[yellow]MEDIUM[/yellow]`, `[red]CRITICAL[/red]`

### Risk Flag Pattern
```python
risk_flags = [
    {'flag': 'Flag name', 'detail': 'Explanation', 'severity': 'HIGH'}
]
```

### Progress Display Pattern (Rich)
```python
with Progress(SpinnerColumn(), TextColumn("..."), BarColumn(), TimeElapsedColumn(),
              console=self.console) as progress:
    task = progress.add_task("[cyan]Description...", total=100)
    progress.update(task, advance=N, description="[cyan]Step...")
    # do work
    progress.update(task, completed=100, description="[green]Done")
```

### Continuous Learning Pattern
After every scan, feed results to ML:
```python
self._feed_to_ml('scan_type', result)
```
This calls `ModelTrainer.scan_result_to_training_data()` in a daemon thread.
Auto-retrain triggers at 50 new samples via `ModelTrainer.auto_retrain_background()`.

### Config Access Pattern
```python
import config
# Use config.CONSTANT directly — never hardcode paths or API keys
config.SHODAN_API_KEY
config.BASE_DIR / 'subdir'
config.is_tor_active()
config.get_proxies()
```

### Database Pattern
All data goes through `modules/database.py` → `data/sentinel.db`.
Tables: scans, findings, iocs, decisions, memory, rl_episodes, tool_stats.

### Evidence Pattern
```python
self.evidence.add_evidence('scan_type', result_dict)
```
Called after every scan to maintain chain of custody.

---

## Semantic Patterns

### Multi-Selector Fallback (HTML Extraction)
```python
def _get_text_by_selectors(self, soup, selectors):
    for selector in selectors:
        element = soup.select_one(selector)
        if element:
            text = element.get_text(strip=True)
            if text:
                return text
    return ''
```
Always provide multiple CSS selectors as fallback — platforms change their HTML frequently.

### Lazy Import Pattern
Heavy imports (torch, sklearn, etc.) are done inside methods, not at module top:
```python
def _train_threat_classifier(self):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    ...
```
This prevents import errors when optional dependencies are missing.

### Thread Safety Pattern
Background tasks use daemon threads:
```python
t = threading.Thread(target=_run, daemon=True, name='sentinel-retrain')
t.start()
```
Locks for exclusive operations:
```python
_retrain_lock = threading.Lock()
if not _retrain_lock.acquire(blocking=False):
    return False  # already running
try:
    ...
finally:
    _retrain_lock.release()
```

### Input Sanitization Pattern
```python
def _validate_target(self, target):
    valid_patterns = [
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Email
        r'^@?[a-zA-Z0-9_]{1,50}$',  # Username
        r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'  # Domain
    ]
    return any(re.match(pattern, target) for pattern in valid_patterns)

def _sanitize_filename(self, filename):
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    return sanitized.lstrip('._/')[:100]
```

### JSONL Data Storage Pattern
Training data stored as JSONL (one JSON object per line):
```python
with open(data_file, 'a') as f:
    f.write(json.dumps({'text': text, 'label': label, 'url': url}) + '\n')
```
Reading:
```python
data = [json.loads(line) for line in f if line.strip()]
```

### Report Save Pattern
Every scan saves three files:
```python
paths = {
    'json':    f"reports/{scan_type}_{target}_{timestamp}.json",
    'summary': f"reports/{scan_type}_{target}_{timestamp}_summary.txt",
    'html':    f"reports/{scan_type}_{target}_{timestamp}.html",
}
self.session_data['last_paths'] = paths
```
PDF is auto-generated after HTML via `self.pdf.export_scan(paths)`.

---

## Frequently Used Idioms

### URL Prefix Stripping
```python
import re as _re
target = _re.sub(r'^https?://', '', target).rstrip('/')
```

### Tor Session
```python
from modules.utils import tor_session
session = tor_session()  # returns requests.Session with SOCKS5 proxy
```

### Rate-Limited Requests
```python
from modules.utils import RateLimiter
# or use config.RATE_LIMIT_REQUESTS / config.RATE_LIMIT_PERIOD
```

### Path Construction
```python
from pathlib import Path
import config
output_dir = config.BASE_DIR / 'reports'
output_dir.mkdir(exist_ok=True)
```

### Telegram Alert After Scan
```python
self.notifier.alert_bugbounty(target, report_data)
self.notifier.alert_recon(target, report_data)
self.notifier.alert_breach(target, result)
```

### ML Threat Prediction
```python
from modules.ml_engine.trainer import ModelTrainer
trainer = ModelTrainer()
result = trainer.predict_threat(text)
# result: {'label': 'HIGH', 'confidence': 0.87, 'probabilities': {...}}
```

### SentinelNet Prediction
```python
from modules.ml_engine.sentinel_net import SentinelNet
# Used via decision_engine.py — not called directly in most modules
```

---

## Anti-Patterns to Avoid

- Never hardcode API keys — always use `config.VARIABLE` or `os.getenv()`
- Never hardcode file paths — always use `config.BASE_DIR / 'path'`
- Never block the main thread with heavy ML operations — use daemon threads
- Never call `sys.exit()` inside modules — only in `main.py` entry point
- Never import heavy dependencies at module top level — use lazy imports inside methods
- Never store PII (emails, phones) in ML training data — use anonymized descriptions
- Never skip `try/except` around subprocess calls — binaries may not exist
- Never use `print()` in modules — always use `logger.info/warning/error/debug()`
- In main.py handlers, always use `self.console.print()` for user output
