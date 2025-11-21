#!/bin/bash
# Script to run code coverage analysis for mtls_safeguard

echo "=== mTLS Safeguard Code Coverage ==="
echo ""

# Check if cargo-tarpaulin is installed
if ! command -v cargo-tarpaulin &> /dev/null; then
    echo "Installing cargo-tarpaulin..."
    cargo install cargo-tarpaulin
fi

echo "Running code coverage analysis..."
echo ""

# Run tarpaulin with HTML output
cargo tarpaulin \
    --out Html \
    --out Xml \
    --output-dir coverage \
    --timeout 120 \
    --verbose

echo ""
echo "=== Coverage Report Generated ==="
echo "HTML Report: coverage/index.html"
echo "XML Report: coverage/cobertura.xml"
echo ""
echo "Open the HTML report with:"
echo "  xdg-open coverage/index.html"
echo ""
