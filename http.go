package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type httpContext struct {
	types.DefaultHttpContext
	contextID uint32
	config    *Config
}

func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	ip, err := proxywasm.GetHttpRequestHeader("x-forwarded-for")
	if err != nil {
		ipBytes, _ := proxywasm.GetProperty([]string{"source", "address"})
		ip = string(ipBytes)
	}

	// Check decision
	key := fmt.Sprintf("decision:ip:%s", ip)
	data, _, err := proxywasm.GetSharedData(key)

	if err == nil && len(data) > 0 {
		var decision Decision
		if err := json.Unmarshal(data, &decision); err == nil {
			proxywasm.LogWarnf("Blocking IP %s: %s", ip, decision.Scenario)

			if err := proxywasm.SendHttpResponse(403, [][2]string{
				{"content-type", "text/plain"},
			}, []byte("Access Denied"), -1); err != nil {
				proxywasm.LogErrorf("failed to send response: %v", err)
			}

			return types.ActionPause
		}
	}

	// Send AppSec event async
	if ctx.config.CrowdSec.AppSec.Enabled {
		go ctx.sendAppSecEvent(ip)
	}

	return types.ActionContinue
}

func (ctx *httpContext) sendAppSecEvent(ip string) {
	path, _ := proxywasm.GetHttpRequestHeader(":path")
	method, _ := proxywasm.GetHttpRequestHeader(":method")

	event := AppSecEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		IP:        ip,
		URI:       path,
		Method:    method,
	}

	body, err := json.Marshal(event)
	if err != nil {
		return
	}

	headers := [][2]string{
		{":method", "POST"},
		{":path", "/v1/appsec/event"},
		{":authority", ctx.config.CrowdSec.AppSec.URL},
		{"x-api-key", ctx.config.CrowdSec.AppSec.Key},
		{"content-type", "application/json"},
	}

	_, err = proxywasm.DispatchHttpCall(
		"crowdsec_appsec",
		headers,
		body,
		nil,
		2000,
		func(numHeaders, bodySize, numTrailers int) {
			// Async callback, ignore response
		},
	)

	if err != nil {
		proxywasm.LogWarnf("failed to send AppSec event: %v", err)
	}
}

type AppSecEvent struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	URI       string `json:"uri"`
	Method    string `json:"method"`
}
