#!/bin/bash

echo "=== Testing CrowdSec WASM Bouncer ==="
echo

# Test normal request
echo "1. Testing normal request (should pass):"
curl -v http://localhost:8000/
echo
echo

# Test with blocked IP (set X-Forwarded-For)
echo "2. Testing blocked IP 1.2.3.4 (should block if in decisions):"
curl -v -H "X-Forwarded-For: 1.2.3.4" http://localhost:8000/
echo
echo

# Check Envoy admin stats
echo "3. Checking Envoy stats:"
curl -s http://localhost:9901/stats | grep wasm
echo

# Check Envoy config
echo "4. Checking WASM filter config:"
curl -s http://localhost:9901/config_dump | jq '.configs[] | select(.["@type"] | contains("HttpConnectionManager"))' | head -50
