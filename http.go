package main

import (
	"fmt"
	"strconv"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type httpContext struct {
	types.DefaultHttpContext
	contextID uint32
	config    *Config
	plugin    *pluginContext
}

func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	ip, err := proxywasm.GetHttpRequestHeader("x-forwarded-for")
	if err != nil {
		ipBytes, _ := proxywasm.GetProperty([]string{"source", "address"})
		ip = string(ipBytes)
	}

	// Check decision in plugin's in-memory map
	key := fmt.Sprintf("Ip:%s", ip)
	if decision, found := ctx.plugin.decisions[key]; found {
		proxywasm.LogWarnf("Blocking IP %s: %s", ip, decision.Scenario)

		if err := proxywasm.SendHttpResponse(403, [][2]string{
			{"content-type", "text/plain"},
		}, []byte("Access Denied"), -1); err != nil {
			proxywasm.LogErrorf("failed to send response: %v", err)
		}

		return types.ActionPause
	}

	// Send AppSec event async (non-blocking via DispatchHttpCall)
	if ctx.config.CrowdSec.AppSec.Enabled {
		ctx.sendAppSecEvent(ip)
	}

	return types.ActionContinue
}

func (ctx *httpContext) sendAppSecEvent(ip string) {
	var err error
	path, _ := proxywasm.GetHttpRequestHeader(":path")
	method, _ := proxywasm.GetHttpRequestHeader(":method")
	host, _ := proxywasm.GetHttpRequestHeader(":host")
	user_agent, _ := proxywasm.GetHttpRequestHeader(":user-agent")

	body := []byte{}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		content_lenght, _ := proxywasm.GetHttpRequestHeader(":content-length")
		bodySize, _ := strconv.Atoi(content_lenght)
		if bodySize > 100000 {
			bodySize = 100000
		}
		body, _ = proxywasm.GetHttpRequestBody(0, bodySize)
	}

	headers := [][2]string{
		{":method", "POST"},
		{":path", "/v1/appsec/event"},
		{":authority", ""},
		{"X-Crowdsec-Appsec-Ip", ip},
		{"X-Crowdsec-Appsec-Uri", path},
		{"X-Crowdsec-Appsec-Host", host},
		{"X-Crowdsec-Appsec-Verb", method},
		{"X-Crowdsec-Appsec-User-Agent", user_agent},
		{"X-Crowdsec-Appsec-Api-Key", ctx.config.CrowdSec.AppSec.Key},
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
