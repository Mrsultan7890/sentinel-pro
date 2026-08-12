# Contributing to The Sentinel Pro

First off — thanks for taking the time to contribute! 🎉

---

## Ways to Contribute

- **Bug reports** — found something broken? Open an issue
- **Feature requests** — have an idea? Open an issue with `[Feature]` in the title
- **Code improvements** — fix a bug, improve performance, add a module
- **Documentation** — improve README, add examples, fix typos
- **New OSINT sources** — add new platforms/APIs to existing modules
- **Payload additions** — add new attack payloads to `sentinel_proxy/payloads/`

---

## Before You Start

1. Check [existing issues](https://github.com/Mrsultan7890/sentinel-pro/issues) — someone may already be working on it
2. For big changes — open an issue first to discuss before writing code
3. For small fixes (typos, bugs) — just open a PR directly

---

## Setting Up Dev Environment

```bash
git clone https://github.com/Mrsultan7890/sentinel-pro.git
cd sentinel-pro
bash setup.sh
source venv/bin/activate
```

---

## Making Changes

```bash
# 1. Fork the repo on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/sentinel-pro.git
cd sentinel-pro

# 3. Create a branch
git checkout -b fix/your-bug-description
# or
git checkout -b feat/your-feature-name

# 4. Make your changes

# 5. Test it works
python3 main.py

# 6. Commit
git add .
git commit -m "fix: describe what you fixed"
# or
git commit -m "feat: describe what you added"

# 7. Push and open PR
git push origin fix/your-bug-description
```

---

## Commit Message Format

```
fix: short description       # bug fix
feat: short description      # new feature
docs: short description      # documentation only
refactor: short description  # code cleanup, no behavior change
perf: short description      # performance improvement
```

---

## Code Style

- **Python** — follow existing code style, no strict linter enforced
- **Go** — run `gofmt` before committing
- **Rust** — run `cargo fmt` before committing
- Keep functions small and focused
- Add comments only where logic is non-obvious
- No hardcoded API keys or credentials — use `.env`

---

## Reporting Bugs

Open an issue with:

1. **What happened** — describe the bug
2. **Steps to reproduce** — exact commands you ran
3. **Expected behavior** — what should have happened
4. **Environment** — OS, Python version, output of `sentinel-pro> status`
5. **Error output** — paste the full error/traceback

---

## Feature Requests

Open an issue with `[Feature]` in the title and describe:

1. **What** — what feature do you want
2. **Why** — what problem does it solve
3. **How** — rough idea of implementation (optional)

---

## Areas That Need Help

- New OSINT platform integrations (`modules/recon/`)
- Additional bug bounty scanners (`modules/bugbounty/`)
- SentinelProxy tab improvements (`sentinel_proxy/ui/tabs/`)
- Sentinel Intel new transforms (`sentinel_intel/engines/`)
- ML model improvements (`modules/ml_engine/`)
- Better error handling and edge cases
- Performance optimizations in Go/Rust services

---

## Legal

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).

Only contribute code you have the right to contribute. Do not add code that enables illegal activity beyond authorized security testing.

---

**Questions?** Open an issue or reach out on Instagram [@who_is_the_black_hat](https://www.instagram.com/who_is_the_black_hat)
