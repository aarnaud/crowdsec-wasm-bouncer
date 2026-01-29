package main

import (
	"encoding/json"
	"fmt"
	"strconv"

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
}

type Config struct {
	CrowdSec CrowdSecConfig `json:"crowdsec"`
}

type CrowdSecConfig struct {
	LAPI   LAPIConfig   `json:"lapi"`
	AppSec AppSecConfig `json:"appsec"`
}

type LAPIConfig struct {
	Cluster  string `json:"cluster"`
	Key      string `json:"key"`
	SyncFreq int    `json:"sync_freq,omitempty"` // seconds, default 10
}

type AppSecConfig struct {
	Enabled       bool   `json:"enabled"`
	AsyncMode     bool   `json:"async_mode,omitempty"`
	Cluster       string `json:"cluster,omitempty"`
	Key           string `json:"key,omitempty"`
	FailOpen      bool   `json:"fail_open,omitempty"`
	ForwardBody   bool   `json:"forward_body,omitempty"`
	MaxBodySizeKB int    `json:"max_body_size_kb,omitempty"` // Default: 100KB
}

func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	defer func() {
		if err := recover(); err != nil {
			proxywasm.LogCriticalf("crashed during OnPluginStart: %v", err)
		}
	}()
	proxywasm.LogInfof("CrowdSec Bouncer context(%d) is starting...", ctx.contextID)
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
		config.CrowdSec.LAPI.SyncFreq = 10
	}
	if config.CrowdSec.AppSec.MaxBodySizeKB == 0 {
		config.CrowdSec.AppSec.MaxBodySizeKB = 100 // Default: 100KB
	}

	ctx.config = &config
	ctx.firstSync = true

	proxywasm.LogInfof("CrowdSec Plugin started - LAPI cluster: %s, AppSec cluster: %s, Appsec enabled: %v",
		ctx.config.CrowdSec.LAPI.Cluster, ctx.config.CrowdSec.AppSec.Cluster, ctx.config.CrowdSec.AppSec.Enabled)

	// DON'T sync during OnPluginStart - let first OnTick handle it
	// This avoids race conditions when multiple workers start simultaneously

	// Schedule periodic sync
	syncMillis := uint32(ctx.config.CrowdSec.LAPI.SyncFreq * 1000) // Convert seconds to milliseconds
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

	// Try to acquire lock atomically
	lockData, cas, err := proxywasm.GetSharedData(syncLockKey)

	// If lock exists and has data, another thread is syncing
	if err == nil && len(lockData) > 0 {
		proxywasm.LogDebugf("Sync already in progress (context %d), skipping", ctx.contextID)
		return
	}

	// Try to set lock with CAS - only one thread will succeed
	err = proxywasm.SetSharedData(syncLockKey, []byte("locked"), cas)
	if err != nil {
		// Another thread acquired the lock first (CAS failed)
		proxywasm.LogDebugf("Failed to acquire sync lock (context %d), another thread won", ctx.contextID)
		return
	}

	proxywasm.LogInfof("Context %d acquired sync lock, starting sync (startup=%v)", ctx.contextID, startup)

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
		{"user-agent", fmt.Sprintf("crowdsec-wasm-bouncer/ctx-%d", ctx.contextID)},
	}

	calloutID, err := proxywasm.DispatchHttpCall(
		ctx.config.CrowdSec.LAPI.Cluster,
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
		if err := proxywasm.SetSharedData("crowdsec_sync_lock", nil, 0); err != nil {
			proxywasm.LogErrorf("Failed to release sync lock: %v", err)
		} else {
			proxywasm.LogInfof("Context %d released sync lock", ctx.contextID)
		}
	}()

	respheaders, err := proxywasm.GetHttpCallResponseHeaders()
	if err != nil {
		proxywasm.LogErrorf("failed to get lapi decision response headers: %v", err)
		return
	}
	status := 0
	for _, header := range respheaders {
		if header[0] == ":status" {
			status, _ = strconv.Atoi(header[1])
		}
	}
	if status == 503 {
		proxywasm.LogErrorf("failed to call lapi decision endpoint")
		return
	}

	body, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
	if err != nil {
		proxywasm.LogErrorf("failed to get LAPI decisions response body: %v", err)
		return
	}
	var resp DecisionsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		proxywasm.LogErrorf("failed to parse LAPI decisions response: %v", err)
		return
	}

	// Update shared data
	for _, d := range resp.New {
		key := fmt.Sprintf("%s:%s", d.Scope, d.Value)
		proxywasm.SetSharedData(key, []byte(fmt.Sprintf("%s_%s", d.Type, d.Scenario)), 0)
	}

	for _, d := range resp.Deleted {
		key := fmt.Sprintf("%s:%s", d.Scope, d.Value)
		proxywasm.SetSharedData(key, nil, 0)
	}

	proxywasm.LogInfof("Context %d synced decisions: +%d new, -%d deleted",
		ctx.contextID, len(resp.New), len(resp.Deleted))
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
