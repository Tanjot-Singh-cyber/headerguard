# HeaderGuard

HTTP security analyzer that checks websites across three layers — HTTP headers, TLS/SSL configuration, and AI-powered contextual analysis.

## What it does

Paste any URL and HeaderGuard gives you:
- A security grade (A+ to F)
- Risk level (Critical / High / Medium / Low)
- Detailed findings across three analysis layers

## Three-layer analysis

### Layer 7 — HTTP Security Headers
Rule-based checks for six critical headers:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Each header is graded as present / weak / missing with attack scenario explanations and fix recommendations.

### Layer 4 — TLS/SSL Analysis
Direct TLS inspection using Python's ssl and socket libraries:
- Protocol version (TLS 1.3 / 1.2 / legacy)
- Cipher suite strength
- Certificate expiry tracking
- Self-signed certificate detection
- Hostname mismatch detection

Critical TLS findings drop the overall grade.

### AI Contextual Analysis
Gemini API integration that reads the full scan result and provides:
- Plain English security summary
- False positive detection — flags headers that may not be needed based on context
- Prioritized fix list
- Confidence score

## Why this matters
Rule-based scanners treat every missing header as equally bad regardless of context. HeaderGuard V2 uses AI to reduce false positives — for example, flagging a missing CSP as lower risk on a static site with no JavaScript.

## Tech stack
- Python / Flask
- requests, ssl, socket (standard library)
- Google Gemini API
- Vanilla JS frontend

## Versions
- v1.0.0 — Rule-based HTTP header analysis
- v2.0.0 — Added TLS/SSL layer + AI contextual analysis

## Setup
```bash
git clone https://github.com/Tanjot-Singh-cyber/headerguard
cd headerguard
pip install flask requests
# Add GEMINI_API_KEY to environment
python app.py
```

## Roadmap
- V3 — Packet capture, unified score, fix generator, PDF export
- V4 — CI/CD GitHub Action, PR bot with line-level fixes
