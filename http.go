package main

import (
	"fmt"
	"strconv"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type httpContext struct {
	types.DefaultHttpContext
	contextID        uint32
	config           *Config
	plugin           *pluginContext
	ip               string
	path             string
	method           string
	host             string
	userAgent        string
	bodyData         []byte
	totalBodySize    int
	totalBodySent    int
	appSecInProgress bool
}

func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	ip, err := proxywasm.GetHttpRequestHeader("x-forwarded-for")
	if err != nil {
		ipBytes, _ := proxywasm.GetProperty([]string{"source", "address"})
		ip = string(ipBytes)
	}
	ctx.ip = ip

	// Store request metadata for AppSec
	ctx.path, _ = proxywasm.GetHttpRequestHeader(":path")
	ctx.method, _ = proxywasm.GetHttpRequestHeader(":method")
	ctx.userAgent, _ = proxywasm.GetHttpRequestHeader("user-agent")

	ctx.host, err = proxywasm.GetHttpRequestHeader(":authority")
	if err != nil {
		propHostRaw, _ := proxywasm.GetProperty([]string{"request", "host"})
		ctx.host = string(propHostRaw)
	}

	// Check decision in SharedData
	key := fmt.Sprintf("ip:%s", ip)
	if decision, _, err := proxywasm.GetSharedData(key); err == nil && len(decision) > 0 {
		proxywasm.LogWarnf("Blocking IP %s: %s", ip, string(decision))

		if err := proxywasm.SendHttpResponse(403, [][2]string{
			{"content-type", "text/plain"},
		}, []byte("Access Denied"), -1); err != nil {
			proxywasm.LogErrorf("failed to send response: %v", err)
		}

		return types.ActionPause
	}

	// If AppSec is disabled, continue
	if !ctx.config.CrowdSec.AppSec.Enabled {
		return types.ActionContinue
	}

	// Check if we need to wait for body
	needsBody := ctx.config.CrowdSec.AppSec.ForwardBody &&
		(ctx.method == "POST" || ctx.method == "PUT" || ctx.method == "PATCH")

	if !needsBody {
		// No body needed, send AppSec event now
		ctx.sendAppSecEvent()
		if !ctx.config.CrowdSec.AppSec.AsyncMode {
			return types.ActionPause
		}
		return types.ActionContinue
	}

	// Get content-length for body size tracking
	contentLengthHeader, _ := proxywasm.GetHttpRequestHeader("content-length")
	ctx.totalBodySize, _ = strconv.Atoi(contentLengthHeader)

	// If endOfStream, body is complete (arrived with headers or no body)
	if endOfStream {
		// Small body case: read it now since OnHttpRequestBody won't be called
		if ctx.totalBodySize > 0 {
			maxBodySizeBytes := ctx.config.CrowdSec.AppSec.MaxBodySizeKB * 1024
			readSize := ctx.totalBodySize
			if readSize > maxBodySizeBytes {
				readSize = maxBodySizeBytes
			}

			body, err := proxywasm.GetHttpRequestBody(0, readSize)
			if err != nil {
				proxywasm.LogWarnf("Failed to read request body: %v", err)
			} else {
				ctx.bodyData = body
				ctx.totalBodySent = len(body)
			}
		}

		ctx.sendAppSecEvent()
		if !ctx.config.CrowdSec.AppSec.AsyncMode {
			return types.ActionPause
		}
		return types.ActionContinue
	}

	// Large body case: wait for OnHttpRequestBody to be called
	return types.ActionContinue
}

func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	// Only handle body if AppSec is enabled and needs it
	if !ctx.config.CrowdSec.AppSec.Enabled || !ctx.config.CrowdSec.AppSec.ForwardBody {
		return types.ActionContinue
	}

	// Calculate max body size in bytes
	maxBodySizeBytes := ctx.config.CrowdSec.AppSec.MaxBodySizeKB * 1024

	// Check if we've already sent max bytes
	if ctx.totalBodySent >= maxBodySizeBytes {
		// Already sent max, just continue
		if endOfStream {
			proxywasm.LogDebugf("Body transfer complete: sent %d bytes (capped at %d)",
				ctx.totalBodySent, maxBodySizeBytes)
		}
		return types.ActionContinue
	}

	// Read current chunk
	readSize := bodySize
	if ctx.totalBodySent+bodySize > maxBodySizeBytes {
		readSize = maxBodySizeBytes - ctx.totalBodySent
	}

	if readSize > 0 {
		chunk, err := proxywasm.GetHttpRequestBody(ctx.totalBodySent, readSize)
		if err != nil {
			proxywasm.LogWarnf("Failed to read request body chunk: %v", err)
		} else {
			// Accumulate for now - we still need to buffer for DispatchHttpCall
			ctx.bodyData = append(ctx.bodyData, chunk...)
			ctx.totalBodySent += len(chunk)
		}
	}

	// If this is the end of stream, send complete body to AppSec
	if endOfStream {
		if ctx.totalBodySent < ctx.totalBodySize {
			proxywasm.LogDebugf("Body truncated: sent %d of %d bytes (max: %d bytes)",
				ctx.totalBodySent, ctx.totalBodySize, maxBodySizeBytes)
		}

		ctx.sendAppSecEvent()
		if !ctx.config.CrowdSec.AppSec.AsyncMode {
			return types.ActionPause
		}
	}

	return types.ActionContinue
}

func (ctx *httpContext) sendAppSecEvent() {
	headers := [][2]string{
		{":method", "POST"},
		{":path", "/"},
		{":authority", ctx.host},
		{"X-Crowdsec-Appsec-Ip", ctx.ip},
		{"X-Crowdsec-Appsec-Uri", ctx.path},
		{"X-Crowdsec-Appsec-Host", ctx.host},
		{"X-Crowdsec-Appsec-Verb", ctx.method},
		{"X-Crowdsec-Appsec-User-Agent", ctx.userAgent},
		{"X-Crowdsec-Appsec-Api-Key", ctx.config.CrowdSec.AppSec.Key},
	}

	_, err := proxywasm.DispatchHttpCall(
		ctx.config.CrowdSec.AppSec.Cluster,
		headers,
		ctx.bodyData, // Send accumulated body data
		nil,
		2000,
		func(numHeaders, bodySize, numTrailers int) {
			// Async callback
			if ctx.config.CrowdSec.AppSec.AsyncMode {
				return
			}

			status := 503
			respheaders, err := proxywasm.GetHttpCallResponseHeaders()
			if err != nil {
				proxywasm.LogErrorf("failed to get AppSec response headers: %v", err)
				return
			}
			for _, header := range respheaders {
				if header[0] == ":status" {
					status, _ = strconv.Atoi(header[1])
				}
			}

			if status == 503 {
				proxywasm.LogErrorf("AppSec API unavailable")
				if ctx.config.CrowdSec.AppSec.FailOpen {
					proxywasm.ResumeHttpRequest()
					return
				}
				proxywasm.LogWarnf("FailOpen disabled, denying request")
			}
			if status == 200 {
				proxywasm.ResumeHttpRequest()
				return
			}
			proxywasm.LogWarnf("AppSec blocking request from %s", ctx.ip)
			if err := proxywasm.SendHttpResponse(403, [][2]string{
				{"content-type", "text/plain"},
			}, []byte("AppSec Access Denied"), -1); err != nil {
				proxywasm.LogErrorf("failed to send response: %v", err)
			}
		},
	)

	if err != nil {
		proxywasm.LogWarnf("failed to send AppSec event: %v", err)
	}
}
