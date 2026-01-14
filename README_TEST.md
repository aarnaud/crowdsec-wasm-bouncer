# Local Testing Guide

## Prerequisites

1. **Port-forward CrowdSec services:**
   ```bash
   # Terminal 1: LAPI
   kubectl port-forward svc/crowdsec-lapi 8080:8080
   
   # Terminal 2: AppSec
   kubectl port-forward svc/crowdsec-appsec 7422:7422
   ```

2. **Get API keys:**
   ```bash
   # Get LAPI bouncer key
   kubectl exec -it deployment/crowdsec -- cscli bouncers add wasm-bouncer
   
   # Get AppSec key
   kubectl get secret crowdsec-appsec-key -o jsonpath='{.data.key}' | base64 -d
   ```

## Setup

1. **Update envoy.yaml with your keys:**
   ```bash
   vim envoy.yaml
   # Replace YOUR_LAPI_KEY_HERE and YOUR_APPSEC_KEY_HERE
   ```

2. **Build WASM:**
   ```bash
   make build
   ```

3. **Run Envoy locally:**
   ```bash
   # Option 1: Docker
   docker run --rm --name envoy \
     --network host \
     -v $(pwd)/envoy.yaml:/etc/envoy/envoy.yaml \
     -v $(pwd)/plugin.wasm:/etc/envoy/plugin.wasm \
     envoyproxy/envoy:v1.28-latest
   
   # Option 2: Native (if installed)
   envoy -c envoy.yaml
   ```

## Testing

```bash
# Run test script
./test.sh

# Or manual tests:

# 1. Test normal request
curl -v http://localhost:8000/

# 2. Test with specific IP
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8000/

# 3. Add test decision in CrowdSec
kubectl exec -it deployment/crowdsec -- \
  cscli decisions add --ip 1.2.3.4 --duration 1h --type ban

# 4. Wait 30s for sync, then test blocked IP
sleep 30
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8000/
# Should return: 403 Access Denied

# 5. Check Envoy logs
docker logs envoy
# Look for: "Synced decisions", "Blocking IP"
```

## Monitoring

```bash
# Envoy admin interface
open http://localhost:9901

# Check stats
curl http://localhost:9901/stats | grep wasm

# Check logs
curl http://localhost:9901/logging
```

## Debugging

### WASM not loading
```bash
# Check Envoy logs
docker logs envoy 2>&1 | grep -i wasm

# Verify file exists
ls -lh plugin.wasm
```

### No decisions syncing
```bash
# Check LAPI connectivity
curl http://localhost:8080/v1/decisions/stream \
  -H "X-Api-Key: YOUR_LAPI_KEY"

# Check envoy logs for sync messages
docker logs envoy 2>&1 | grep "Synced decisions"
```

### IP not blocked
```bash
# Verify decision exists
kubectl exec -it deployment/crowdsec -- cscli decisions list

# Check if IP format matches (should be "ip:1.2.3.4")
# Check Envoy logs for "Blocking IP" message
```

## Cleanup

```bash
# Stop Envoy
docker stop envoy

# Stop port-forwards
killall kubectl
```
