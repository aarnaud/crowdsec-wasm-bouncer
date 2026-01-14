package main

import (
	"encoding/json"
	"fmt"
	"math/rand"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type pluginContext struct {
	types.DefaultPluginContext
	contextID uint32
	config    *Config
	calloutID uint32
	firstSync bool
	//decisions map[string]Decision
	bouncerId int
}

type Config struct {
	CrowdSec CrowdSecConfig `json:"crowdsec"`
}

type CrowdSecConfig struct {
	LAPI   LAPIConfig   `json:"lapi"`
	AppSec AppSecConfig `json:"appsec"`
}

type LAPIConfig struct {
	URL      string `json:"url"`
	Key      string `json:"key"`
	SyncFreq int    `json:"sync_freq"` // seconds, default 30
}

type AppSecConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Key     string `json:"key"`
}

func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	ctx.bouncerId = rand.Intn(100000)
	proxywasm.LogInfof("CrowdSec Bouncer id(%d) is starting...", ctx.bouncerId)
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		proxywasm.LogCriticalf("failed to get config: %v", err)
		return types.OnPluginStartStatusFailed
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		proxywasm.LogCriticalf("failed to parse config: %v", err)
		return types.OnPluginStartStatusFailed
	}

	// Set defaults
	if config.CrowdSec.LAPI.SyncFreq == 0 {
		config.CrowdSec.LAPI.SyncFreq = 30
	}

	ctx.config = &config
	ctx.firstSync = true

	proxywasm.LogInfof("CrowdSec Bouncer started - LAPI: %s, AppSec: %v",
		config.CrowdSec.LAPI.URL, config.CrowdSec.AppSec.Enabled)

	// DON'T sync during OnPluginStart - let first OnTick handle it
	// This avoids race conditions when multiple workers start simultaneously

	// Schedule periodic sync
	syncMillis := uint32(config.CrowdSec.LAPI.SyncFreq * 1000) // Convert seconds to milliseconds
	if err := proxywasm.SetTickPeriodMilliSeconds(syncMillis); err != nil {
		proxywasm.LogErrorf("failed to set tick period: %v", err)
	}

	return types.OnPluginStartStatusOK
}

func (ctx *pluginContext) OnTick() {
	// Use firstSync flag to trigger startup=true on first tick
	ctx.syncDecisions(ctx.firstSync)
	ctx.firstSync = false
}

func (ctx *pluginContext) syncDecisions(startup bool) {
	// Use SharedData CAS to prevent multiple threads syncing simultaneously
	syncLockKey := "crowdsec_sync_lock"

	// Try to get existing lock
	_, cas, err := proxywasm.GetSharedData(syncLockKey)
	if err == nil {
		// Lock exists, another thread is syncing
		proxywasm.LogDebugf("Sync already in progress (bouncer %d), skipping", ctx.bouncerId)
		return
	}

	// Try to set lock with CAS (cas should be 0 if key doesn't exist)
	err = proxywasm.SetSharedData(syncLockKey, []byte("locked"), cas)
	if err != nil {
		// Another thread acquired the lock first
		proxywasm.LogDebugf("Failed to acquire sync lock (bouncer %d), skipping", ctx.bouncerId)
		return
	}

	// Use plugin context ID as unique bouncer identifier
	bouncerID := fmt.Sprintf("wasm-ctx-%d", ctx.bouncerId)

	// Only use startup=true on first sync
	path := "/v1/decisions/stream"
	if startup {
		path += "?startup=true"
	}

	headers := [][2]string{
		{":method", "GET"},
		{":path", path},
		{":authority", ""},
		{"X-Api-Key", ctx.config.CrowdSec.LAPI.Key},
		{"user-agent", fmt.Sprintf("crowdsec-wasm-bouncer/%s", bouncerID)},
	}

	calloutID, err := proxywasm.DispatchHttpCall(
		"crowdsec_lapi",
		headers,
		nil,
		nil,
		60000,
		ctx.onLAPIResponse,
	)

	if err != nil {
		proxywasm.LogErrorf("failed to dispatch LAPI call: %v", err)
		// Release lock on error
		proxywasm.SetSharedData(syncLockKey, nil, 0)
		return
	}

	ctx.calloutID = calloutID
}

func (ctx *pluginContext) onLAPIResponse(numHeaders, bodySize, numTrailers int) {
	// Always release the sync lock when done
	defer func() {
		proxywasm.SetSharedData("crowdsec_sync_lock", nil, 0)
	}()

	body, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
	if err != nil {
		proxywasm.LogErrorf("failed to get LAPI response: %v", err)
		return
	}

	var resp DecisionsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		proxywasm.LogErrorf("failed to parse decisions: %v", err)
		return
	}

	// Update shared data
	for _, d := range resp.New {
		key := fmt.Sprintf("%s:%s", d.Scope, d.Value)
		proxywasm.SetSharedData(key, []byte(d.Scenario), 0)
	}

	for _, d := range resp.Deleted {
		key := fmt.Sprintf("%s:%s", d.Scope, d.Value)
		proxywasm.SetSharedData(key, nil, 0)
	}

	proxywasm.LogInfof("Synced decisions: +%d new, -%d deleted",
		len(resp.New), len(resp.Deleted))
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		contextID: contextID,
		config:    ctx.config,
		plugin:    ctx,
	}
}

type DecisionsResponse struct {
	New     []Decision `json:"new"`
	Deleted []Decision `json:"deleted"`
}

type Decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}
