
Bashfist-github-repo
OneMan

OneMan — An unconventional, live-output Bash web pentesting tool.

Features

Live-only output (no files written by default)

Shallow crawl + parameter discovery

Advanced XSS payloads + reflection/context hints

Error-based, boolean-diff, timing-based SQLi checks

Auto-run sqlmap (if present) with recommended flags

Advanced LFI / path traversal payloads

Header fuzzing, parameter mutation fuzzing

JS file endpoint & source-map analyzer

Multipart/form-data XSS probing

Ctrl-C handling to skip long-running tools and continue

Requirements

bash (GNU bash)

curl

python3 (for URL encoding helper)

sqlmap (optional — script will skip if not present)

Usage
chmod +x oneman.sh
./oneman.sh <target_url> [--stealth]
