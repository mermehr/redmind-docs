\
#!/usr/bin/env bash
#
# deep_recon.sh — extended recon workflow
# - TCP or UDP nmap (quick or full)
# - optional gobuster (dir) or ffuf (vhost / virtual-host discovery)
# - optional XML parsing (nmap -oX) for richer banners
# - parallel gobuster runs per port / vhost discovery
#
# Usage:
#   ./deep_recon.sh -t <target> [-o outdir] [-w wordlist] [--no-web] [--quick] [--udp] [--vhosts] [--ffuf] [--xml]
set -Eeuo pipefail

show_help() {
  cat <<'USAGE'
deep_recon.sh - extended host recon

Required:
  -t, --target <host|ip|cidr>    Target to scan

Optional:
  -o, --outdir <dir>             Output directory (default: ./recon_<target>)
  -w, --wordlist <file>          Wordlist for gobuster/ffuf (default: /usr/share/wordlists/dirb/common.txt)
  --no-web                       Skip web enumeration
  --quick                        Quick nmap (top-1000 ports) instead of full TCP port sweep
  --udp                          Run a light UDP probe (nmap -sU top-100 ports)
  --vhosts                       Try virtual-host discovery using ffuf Host header fuzzing (if ffuf installed)
  --ffuf                         Use ffuf for dir discovery instead of gobuster (if ffuf installed)
  --xml                          Keep nmap XML output and let parser read it for richer details
  -h, --help                     Show this help
USAGE
}

# Defaults
TARGET=""
OUTDIR=""
WORDLIST="/usr/share/wordlists/dirb/common.txt"
DO_WEB=1
QUICK=0
DO_UDP=0
DO_VHOSTS=0
USE_FFUF=0
KEEP_XML=0

# Parse args (simple)
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    -o|--outdir) OUTDIR="$2"; shift 2;;
    -w|--wordlist) WORDLIST="$2"; shift 2;;
    --no-web) DO_WEB=0; shift;;
    --quick) QUICK=1; shift;;
    --udp) DO_UDP=1; shift;;
    --vhosts) DO_VHOSTS=1; shift;;
    --ffuf) USE_FFUF=1; shift;;
    --xml) KEEP_XML=1; shift;;
    -h|--help) show_help; exit 0;;
    *) echo "Unknown arg: $1" >&2; show_help; exit 1;;
  esac
done

if [[ -z "${TARGET}" ]]; then
  echo "[!] Target required." >&2; show_help; exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] Missing: $1" >&2; exit 127; } }
need nmap
need python3
if [[ $DO_WEB -eq 1 ]]; then
  if [[ $USE_FFUF -eq 1 ]] ; then need ffuf; else need gobuster; fi
fi
if [[ $DO_VHOSTS -eq 1 ]]; then need ffuf; fi

SAFE_TARGET="$(echo "${TARGET}" | tr '/:\\ ' '_')"
OUTDIR="${OUTDIR:-"./recon_${SAFE_TARGET}"}"
SCANDIR="${OUTDIR}/scans"
WEBDIR="${OUTDIR}/web"
PARSEDIR="${OUTDIR}/parsed"
mkdir -p "${SCANDIR}" "${WEBDIR}" "${PARSEDIR}"

echo "[*] Target: ${TARGET}"
echo "[*] Output: ${OUTDIR}"

NMAP_OUT="${SCANDIR}/nmap_${SAFE_TARGET}.txt"
NMAP_XML="${SCANDIR}/nmap_${SAFE_TARGET}.xml"
NMAP_GNMAP="${SCANDIR}/nmap_${SAFE_TARGET}.gnmap"

if [[ $QUICK -eq 1 ]]; then
  echo "[*] Running quick TCP nmap..."
  nmap -Pn -sC -sV --top-ports 1000 -oN "${NMAP_OUT}" -oX "${NMAP_XML}" -oG "${NMAP_GNMAP}" "${TARGET}"
else
  echo "[*] Running full TCP nmap (-p-)..."
  nmap -Pn -sC -sV -p- --min-rate 3000 --defeat-rst-ratelimit -oN "${NMAP_OUT}" -oX "${NMAP_XML}" -oG "${NMAP_GNMAP}" "${TARGET}"
fi

if [[ $DO_UDP -eq 1 ]]; then
  echo "[*] Running light UDP scan (top-100 common UDP ports)..."
  nmap -sU --top-ports 100 -Pn -oN "${SCANDIR}/nmap_${SAFE_TARGET}_udp.txt" -oX "${SCANDIR}/nmap_${SAFE_TARGET}_udp.xml" "${TARGET}" || true
fi

# Detect common web ports in nmap greppable output
run_web=0
mapfile -t web_ports < <(grep -E '^(80|443|8080|8000|8443)/tcp\\s+open' "${NMAP_OUT}" 2>/dev/null | cut -d'/' -f1 || true)

if [[ ${#web_ports[@]} -gt 0 && $DO_WEB -eq 1 ]]; then
  run_web=1
fi

# Optionally discover vhosts using ffuf Host header fuzzing
VHOST_OUTS=()
if [[ $DO_VHOSTS -eq 1 && ${#web_ports[@]} -gt 0 ]]; then
  echo "[*] Running vhost discovery with ffuf (Host header fuzzing) ..."
  for port in "${web_ports[@]}"; do
    scheme="http"; [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
    out="${WEBDIR}/ffuf_vhosts_${SAFE_TARGET}_${port}.txt"
    ffuf -w "${WORDLIST}" -u "${scheme}://${TARGET}:${port}/" -H "Host: FUZZ" -fs 0 -mc 200 -ac -o "${out}" -of csv || true
    VHOST_OUTS+=("${out}")
  done
fi

# Directory fuzzing: gobuster or ffuf per-port
GOBUSTER_OUTS=()
if [[ $run_web -eq 1 ]]; then
  echo "[*] Running directory discovery on web ports..."
  for port in "${web_ports[@]}"; do
    scheme="http"; [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
    url="${scheme}://${TARGET}:${port}/"
    out="${WEBDIR}/dirs_${SAFE_TARGET}_${port}.txt"
    if [[ $USE_FFUF -eq 1 ]]; then
      ffuf -w "${WORDLIST}" -u "${url}FUZZ" -fs 0 -mc 200 -ac -o "${out}" -of csv || true
    else
      gobuster dir -u "${url}" -w "${WORDLIST}" -q -o "${out}" || true
    fi
    GOBUSTER_OUTS+=("${out}")
  done
else
  echo "[*] No web ports detected or web enumeration disabled."
fi

# Call parser
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="${SCRIPT_DIR}/recon_parser.py"
if [[ ! -x "${PARSER}" ]]; then
  if command -v recon_parser.py >/dev/null 2>&1; then PARSER="$(command -v recon_parser.py)"; fi
fi
if [[ ! -x "${PARSER}" ]]; then echo "[!] recon_parser.py not found next to script or in PATH." >&2; exit 1; fi

PARSE_ARGS=( "${NMAP_OUT}" )
if [[ -f "${NMAP_XML}" && $KEEP_XML -eq 1 ]]; then PARSE_ARGS+=( "--xml" "${NMAP_XML}" ); fi
for f in "${GOBUSTER_OUTS[@]}"; do PARSE_ARGS+=( "${f}" ); done
for f in "${VHOST_OUTS[@]}"; do PARSE_ARGS+=( "${f}" ); done

echo "[*] Parsing results ..."
python3 "${PARSER}" "${PARSE_ARGS[@]}" --outdir "${PARSEDIR}" || true

echo "[+] Done. Results in: ${OUTDIR}"
