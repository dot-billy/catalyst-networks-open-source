#!/bin/bash
# Build Tailwind CSS from templates using the standalone CLI.
# Usage:
#   ./build-tailwind.sh          # one-shot build
#   ./build-tailwind.sh --watch  # watch mode for development

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Download tailwindcss CLI if not present
if [ ! -f ./tailwindcss ]; then
    echo "Downloading Tailwind CSS standalone CLI..."
    curl -sL "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64" -o tailwindcss
    chmod +x tailwindcss
fi

if [ "$1" = "--watch" ]; then
    echo "Watching for changes..."
    ./tailwindcss -i static/css/tailwind-input.css -o static/css/tailwind-output.css --watch
else
    echo "Building Tailwind CSS..."
    ./tailwindcss -i static/css/tailwind-input.css -o static/css/tailwind-output.css --minify
    echo "Done: static/css/tailwind-output.css"
fi
