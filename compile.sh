#!/bin/bash

GO_FILE="./netforge.go"
OUTPUT_DIR="./build"
mkdir -p $OUTPUT_DIR

PLATFORMS=("linux" "windows" "darwin")

for OS in "${PLATFORMS[@]}"; do
    EXT=""
    if [ "$OS" == "windows" ]; then
        EXT=".exe"
    fi
    echo "[*] Building for $OS..."
    GOOS=$OS GOARCH=amd64 CGO_ENABLED=0 go build -o "$OUTPUT_DIR/netforge_$OS$EXT" $GO_FILE
    if [ $? -eq 0 ]; then
        echo "[+] Success: $OUTPUT_DIR/netforge_$OS$EXT"
    else
        echo "[-] Failed: $OS"
    fi
done
echo "[*] All builds completed!"