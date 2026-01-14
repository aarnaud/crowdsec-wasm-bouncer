package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type pluginContext struct {
	types.DefaultPluginContext
	config    *Config
	calloutID uint32
	firstSync bool
	decisions map[string]Decision
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
	ctx.decisions = make(map[string]Decision)

	proxywasm.LogInfof("CrowdSec Bouncer started - LAPI: %s, AppSec: %v",
		config.CrowdSec.LAPI.URL, config.CrowdSec.AppSec.Enabled)

	// Initial sync
	ctx.syncDecisions()

	// Schedule periodic sync
	syncDuration := time.Duration(config.CrowdSec.LAPI.SyncFreq) * time.Second
	if err := proxywasm.SetTickPeriodMilliSeconds(uint32(syncDuration.Milliseconds())); err != nil {
		proxywasm.LogErrorf("failed to set tick period: %v", err)
	}

	return types.OnPluginStartStatusOK
}

func (ctx *pluginContext) OnTick() {
	ctx.syncDecisions()
}

func (ctx *pluginContext) syncDecisions() {
	// Use plugin context ID as bouncer identifier
	bouncerID := fmt.Sprintf("wasm-plugin-%d", time.Now().Unix())

	// Only use startup=true on first sync
	path := "/v1/decisions/stream"
	if ctx.firstSync {
		path += "?startup=true"
		ctx.firstSync = false
	}

	headers := [][2]string{
		{":method", "GET"},
		{":path", path},
		{":authority", ctx.config.CrowdSec.LAPI.URL},
		{"x-api-key", ctx.config.CrowdSec.LAPI.Key},
		{"user-agent", fmt.Sprintf("crowdsec-wasm-bouncer/%s", bouncerID)},
	}

	calloutID, err := proxywasm.DispatchHttpCall(
		"crowdsec_lapi",
		headers,
		nil,
		nil,
		5000,
		ctx.onLAPIResponse,
	)

	if err != nil {
		proxywasm.LogErrorf("failed to dispatch LAPI call: %v", err)
		return
	}

	ctx.calloutID = calloutID
}

func (ctx *pluginContext) onLAPIResponse(numHeaders, bodySize, numTrailers int) {
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

	// Update in-memory map
	for _, d := range resp.New {
		key := fmt.Sprintf("%s:%s", d.Scope, d.Value)
		ctx.decisions[key] = d
	}

	for _, d := range resp.Deleted {
		key := fmt.Sprintf("%s:%s", d.Scope, d.Value)
		delete(ctx.decisions, key)
	}

	proxywasm.LogInfof("Synced decisions: +%d new, -%d deleted, total: %d",
		len(resp.New), len(resp.Deleted), len(ctx.decisions))
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
