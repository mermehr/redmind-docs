#!/usr/bin/env bash
# kali_tool.sh — Smart tool installer for Linux Mint with Kali + Flatpak/GitHub fallback
# WARNING: Mixing Kali with Mint/Ubuntu can break dependencies. This script pins Kali low
# and only opts into Kali for the requested package.

set -Eeuo pipefail

# ---------- Config ----------
TOOL="${1:-}"
KALI_LIST="/etc/apt/sources.list.d/zzz-kali-temp.list"
KALI_PREF="/etc/apt/preferences.d/zzz-kali-temp.pref"
KEYRINGS_DIR="/etc/apt/keyrings"
KALI_KEYRING="$KEYRINGS_DIR/kali-archive-keyring.gpg"
KALI_URL="http://http.kali.org/kali"
KALI_SUITE="kali-rolling"

# ---------- Colors ----------
GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; NC="\033[0m"

info() {  echo -e "${GREEN}[+]${NC} $*"; }
warn() {  echo -e "${YELLOW}[!]${NC} $*"; }
err()  {  echo -e "${RED}[x]${NC} $*" >&2; }

require_root() {
  if [[ ${EUID} -ne 0 ]]; then err "Please run as root."; exit 1; fi
}

usage() {
  cat <<EOF
Usage: sudo $0 <tool-name> [-y]

Installs <tool-name> by:
  1) Mint/Ubuntu repos
  2) Temporarily enabling Kali (pinned low), optional install from Kali
  3) Fallback: Flatpak search or GitHub search/clone hint

Options:
  -y    Assume 'yes' to prompts (non-interactive Kali install)

Examples:
  sudo $0 gobuster
  sudo $0 seclists -y
EOF
}

# Clean up temp repo & prefs no matter what happens
cleanup() {
  local changed=0
  if [[ -f "$KALI_LIST" ]]; then rm -f "$KALI_LIST"; changed=1; fi
  if [[ -f "$KALI_PREF" ]]; then rm -f "$KALI_PREF"; changed=1; fi
  if (( changed )); then
    apt-get update -qq || true
    info "Cleaned up temporary Kali sources."
  fi
}
trap cleanup EXIT

# ---------- Helpers ----------
have() { command -v "$1" >/dev/null 2>&1; }

apt_show_available() {
  # Return 0 if package has a candidate in current repo set, else 1
  local pkg="$1"
  apt-cache policy "$pkg" 2>/dev/null | awk -F': ' '/Candidate:/ {print $2}' | grep -vq "(none)"
}

mint_install() {
  local pkg="$1"
  info "Installing '$pkg' from Mint/Ubuntu repo…"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
}

ensure_kali_keyring() {
  mkdir -p "$KEYRINGS_DIR"
  if [[ -f "$KALI_KEYRING" ]]; then
    info "Kali keyring present: $KALI_KEYRING"
    return 0
  fi
  warn "Kali keyring not found — fetching…"
  if ! have curl && ! have wget; then
    err "Need curl or wget to fetch the Kali keyring."; exit 1
  fi
  local tmpkey
  tmpkey="$(mktemp)"
  if have curl; then
    curl -fsSL https://archive.kali.org/archive-key.asc -o "$tmpkey"
  else
    wget -qO "$tmpkey" https://archive.kali.org/archive-key.asc
  fi
  if ! have gpg; then
    info "Installing gnupg to dearmor key…"
    apt-get update -qq
    apt-get install -y gnupg
  fi
  gpg --dearmor < "$tmpkey" > "$KALI_KEYRING"
  rm -f "$tmpkey"
  info "Installed Kali keyring: $KALI_KEYRING"
}

add_temp_kali_repo() {
  # Use signed-by and pin Kali low so it won't override base by default
  echo "deb [signed-by=$KALI_KEYRING] $KALI_URL $KALI_SUITE main contrib non-free non-free-firmware" > "$KALI_LIST"
  cat > "$KALI_PREF" <<EOF
Package: *
Pin: origin "http.kali.org"
Pin-Priority: 100
EOF
  info "Added temporary Kali source (pinned low)."
  # Update only this source to minimize impact (also fine to do full update)
  apt-get update \
    -o Dir::Etc::sourcelist="$KALI_LIST" \
    -o Dir::Etc::sourceparts="-" \
    -o APT::Get::List-Cleanup="0" -qq
}

available_in_kali() {
  # Check if Kali provides the package by looking at policy origins
  local pkg="$1"
  apt-cache policy "$pkg" | grep -q "$KALI_URL"
}

kali_install() {
  local pkg="$1" no_recommends="${2:-1}"
  local nr_flag=()
  [[ "$no_recommends" == "1" ]] && nr_flag=(--no-install-recommends)
  info "Installing '$pkg' from Kali ($KALI_SUITE)…"
  # -t kali-rolling ensures we pull from Kali; pinning keeps other deps from mass-upgrading
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${nr_flag[@]}" -t "$KALI_SUITE" "$pkg"
}

flatpak_fallback() {
  local pkg="$1"
  if have flatpak; then
    warn "Searching Flatpak for '$pkg'…"
    flatpak search --columns=application,description "$pkg" || true
    echo -e "${YELLOW}To install (example):${NC} flatpak install flathub <application-id>"
  else
    warn "Flatpak not installed. Open Flathub search in browser…"
    if have xdg-open; then
      xdg-open "https://flathub.org/apps/search/$pkg" >/dev/null 2>&1 || true
    else
      echo "Visit: https://flathub.org/apps/search/$pkg"
    fi
  fi
}

github_fallback() {
  local pkg="$1"
  warn "GitHub search hints for '$pkg'…"
  if have gh; then
    gh search repos --limit 10 "$pkg in:name" || true
    echo -e "${YELLOW}To clone:${NC} gh repo clone <owner>/<repo>"
  else
    echo "If you have 'gh': gh search repos \"$pkg in:name\""
    if have xdg-open; then
      xdg-open "https://github.com/search?q=${pkg}+in%3Aname&type=repositories" >/dev/null 2>&1 || true
    else
      echo "Browse: https://github.com/search?q=${pkg}+in%3Aname&type=repositories"
    fi
  fi
}

# ---------- Main ----------
require_root
if [[ -z "$TOOL" || "${2:-}" == "-h" || "${2:-}" == "--help" ]]; then usage; exit 0; fi
ASSUME_YES=0
[[ "${2:-}" == "-y" ]] && ASSUME_YES=1

# Quick short-circuit: already installed?
if dpkg -s "$TOOL" >/dev/null 2>&1; then
  info "'$TOOL' is already installed."
  exit 0
fi

# 1) Mint/Ubuntu repos
info "Checking Mint/Ubuntu repos for '$TOOL'…"
apt-get update -qq
if apt_show_available "$TOOL"; then
  mint_install "$TOOL"
  exit $?
else
  warn "Not found in Mint/Ubuntu repo."
fi

# 2) Kali (temporary, pinned)
warn "Trying Kali repo (temporarily)…"
ensure_kali_keyring
add_temp_kali_repo

if available_in_kali "$TOOL"; then
  warn "'$TOOL' appears in Kali ($KALI_SUITE). This may pull Kali dependencies."
  if (( ASSUME_YES )); then
    kali_install "$TOOL" "1"
    exit $?
  else
    read -r -p "$(echo -e ${YELLOW}[?] Install from Kali with --no-install-recommends? "(y/N): "${NC})" yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
      kali_install "$TOOL" "1"
      exit $?
    else
      warn "Skipped Kali install."
    fi
  fi
else
  err "'$TOOL' not found in Kali repository."
fi

# 3) Fallbacks
echo
warn "Fallback options for '$TOOL':"
select choice in "Search Flatpak" "Search GitHub" "Quit"; do
  case "$choice" in
    "Search Flatpak") flatpak_fallback "$TOOL"; break ;;
    "Search GitHub")  github_fallback "$TOOL";  break ;;
    "Quit")           break ;;
    *) echo "Select 1-3." ;;
  esac
done
