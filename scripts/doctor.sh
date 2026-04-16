#!/usr/bin/env bash
set -euo pipefail

model="${OLLAMA_MODEL:-llama3.2:1b}"
host="${OLLAMA_HOST:-http://127.0.0.1:11434}"
ok=0

pass() {
  printf '[OK] %s\n' "$1"
}

warn() {
  printf '[WARN] %s\n' "$1"
  ok=1
}

need_command() {
  local cmd="$1"
  local label="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    pass "$label: $(command -v "$cmd")"
  else
    warn "$label is not installed or not in PATH"
  fi
}

need_command go "Go"
need_command did_finder "did_finder"
need_command ollama "Ollama"
need_command nuclei "Nuclei"
need_command curl "curl"

if command -v chromium >/dev/null 2>&1; then
  pass "Chromium: $(command -v chromium)"
elif command -v chromium-browser >/dev/null 2>&1; then
  pass "Chromium: $(command -v chromium-browser)"
elif command -v chrome >/dev/null 2>&1; then
  pass "Chrome: $(command -v chrome)"
else
  warn "Chrome/Chromium not found; -screenshot will not work"
fi

if command -v go >/dev/null 2>&1; then
  pass "$(go version)"
fi

if command -v curl >/dev/null 2>&1; then
  pass "$(curl --version | head -n 1)"
fi

if command -v ollama >/dev/null 2>&1; then
  if curl -fsS --max-time 5 "$host/api/version" >/tmp/did_finder_ollama_version.json; then
    pass "Ollama API reachable at $host ($(cat /tmp/did_finder_ollama_version.json))"
  else
    warn "Ollama API is not reachable at $host"
  fi

  if ollama list | awk 'NR > 1 {print $1}' | grep -Fx "$model" >/dev/null 2>&1; then
    pass "Ollama model installed: $model"
  else
    warn "Ollama model missing: $model (run: make ollama-pull)"
  fi
fi

if command -v nuclei >/dev/null 2>&1; then
  if nuclei -version >/tmp/did_finder_nuclei_version.txt 2>&1; then
    pass "Nuclei version: $(tr '\n' ' ' </tmp/did_finder_nuclei_version.txt)"
  else
    warn "Nuclei is installed but version check failed"
  fi
  if nuclei -templates-version >/tmp/did_finder_nuclei_templates.txt 2>&1; then
    pass "Nuclei templates: $(tr '\n' ' ' </tmp/did_finder_nuclei_templates.txt)"
  else
    warn "Nuclei templates not ready; run: nuclei -update-templates"
  fi
fi

if [ -f "$HOME/.config/did_finder/config.yaml" ]; then
  pass "Config: $HOME/.config/did_finder/config.yaml"
elif [ -f "$HOME/.did_finder.yaml" ]; then
  pass "Config: $HOME/.did_finder.yaml"
else
  warn "No config found; copy config.example.yaml to $HOME/.config/did_finder/config.yaml"
fi

exit "$ok"
