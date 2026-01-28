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

	// Check decision in SharedData - use lowercase "ip" to match CrowdSec scope
	key := fmt.Sprintf("Ip:%s", ip)
	if decision, _, err := proxywasm.GetSharedData(key); err == nil && len(decision) > 0 {
		proxywasm.LogWarnf("Blocking IP %s: %s", ip, string(decision))

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
		// Not AsyncMode
		if !ctx.config.CrowdSec.AppSec.AsyncMode {
			return types.ActionPause
		}
	}

	return types.ActionContinue
}

func (ctx *httpContext) sendAppSecEvent(ip string) {
	var err error
	path, _ := proxywasm.GetHttpRequestHeader(":path")
	method, _ := proxywasm.GetHttpRequestHeader(":method")
	user_agent, _ := proxywasm.GetHttpRequestHeader(":user-agent")

	host, err := proxywasm.GetHttpRequestHeader(":authority")
	if err != nil {
		proxywasm.LogDebugf("Failed to get request :authority value: %v", err)
		propHostRaw, propHostErr := proxywasm.GetProperty([]string{"request", "host"})
		if propHostErr != nil {
			proxywasm.LogWarnf("Failed to get request :authority value and request host value: %v", propHostErr)
		} else {
			host = string(propHostRaw)
		}
	}

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
		{":path", "/"},
		{":authority", host},
		{"X-Crowdsec-Appsec-Ip", ip},
		{"X-Crowdsec-Appsec-Uri", path},
		{"X-Crowdsec-Appsec-Host", host},
		{"X-Crowdsec-Appsec-Verb", method},
		{"X-Crowdsec-Appsec-User-Agent", user_agent},
		{"X-Crowdsec-Appsec-Api-Key", ctx.config.CrowdSec.AppSec.Key},
	}

	_, err = proxywasm.DispatchHttpCall(
		ctx.config.CrowdSec.AppSec.Cluster,
		headers,
		body,
		nil,
		2000,
		func(numHeaders, bodySize, numTrailers int) {
			// Async callback, ignore response
			if ctx.config.CrowdSec.AppSec.AsyncMode {
				return
			}

			status := 503
			respheaders, err := proxywasm.GetHttpCallResponseHeaders()
			if err != nil {
				proxywasm.LogErrorf("failed to get Appsecc response headers: %v", err)
				return
			}
			for _, header := range respheaders {
				if header[0] == ":status" {
					status, _ = strconv.Atoi(header[1])
				}
			}

			if status == 503 {
				proxywasm.LogErrorf("failed to call Appsecc api, service unavailable")
				if ctx.config.CrowdSec.AppSec.FailOpen {
					proxywasm.ResumeHttpRequest()
					return
				}
				proxywasm.LogWarnf("FailOpen is disable, request will be denied")
			}
			if status == 200 {
				proxywasm.ResumeHttpRequest()
				return
			}
			proxywasm.LogWarnf("Appsec is blocking request from %s", ip)
			if err := proxywasm.SendHttpResponse(403, [][2]string{
				{"content-type", "text/plain"},
			}, []byte("AppSec, Access Denied"), -1); err != nil {
				proxywasm.LogErrorf("failed to send response: %v", err)
			}
		},
	)

	if err != nil {
		proxywasm.LogWarnf("failed to send AppSec event: %v", err)
	}
}
