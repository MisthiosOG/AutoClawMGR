#!/usr/bin/env bash
# autoclawpi launcher — Linux/macOS
cd "$(dirname "$0")"

PASSWORD="${PASSWORD:?set WEB_PASSWORD first}"
PORT="${PORT:-8787}"

# Prioritas binary: ./autoclawpi → prebuilt linux64 → build dari source
if [ ! -f ./autoclawpi ]; then
  if [ -f ./autoclawpi-linux64 ]; then
    cp autoclawpi-linux64 autoclawpi
    chmod +x autoclawpi
  else
    echo "Building autoclawpi (butuh Go 1.26+)..."
    go build -o autoclawpi ./cmd/autoclawpi || { echo "Build gagal. Install Go: https://go.dev/dl/ atau pakai autoclawpi-linux64"; exit 1; }
  fi
fi

echo "============================================"
echo "  AutoClawPi - OpenAI-compatible proxy"
echo "============================================"
echo "  Panel : http://localhost:$PORT"
echo "  Login : $PASSWORD"
echo "  API   : /v1/chat/completions, /v1/models"
echo "  Ctrl+C untuk berhenti."
echo "============================================"

./autoclawpi serve --port "$PORT" --web-password "$PASSWORD"
