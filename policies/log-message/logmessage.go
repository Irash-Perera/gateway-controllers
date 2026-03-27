/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package logmessage

import (
	"encoding/json"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	HeaderXRequestID      = "x-request-id"
	FieldNamePayload      = "payload"
	FieldNameHeaders      = "headers"
	ErrMsgMissingReqID    = "<request-id-unavailable>"
	MediationFlowRequest  = "REQUEST"
	MediationFlowResponse = "RESPONSE"
	MediationFlowFault    = "FAULT"
)

// LogMessagePolicy implements logging of request/response payloads and headers
type LogMessagePolicy struct{}

type flowConfig struct {
	logPayload      bool
	logHeaders      bool
	excludedHeaders map[string]struct{}
}

var ins = &LogMessagePolicy{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// Mode returns the processing mode for this policy
func (p *LogMessagePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Process request headers for logging
		RequestBodyMode:    policy.BodyModeBuffer,    // Need request body for logging
		ResponseHeaderMode: policy.HeaderModeProcess, // Process response headers for logging
		ResponseBodyMode:   policy.BodyModeStream,    // Need response body for logging
	}
}

// LogRecord represents the structure of log data
type LogRecord struct {
	MediationFlow string                 `json:"mediation-flow"`
	RequestID     string                 `json:"request-id"`
	HTTPMethod    string                 `json:"http-method"`
	ResourcePath  string                 `json:"resource-path"`
	Payload       string                 `json:"payload,omitempty"`
	Headers       map[string]interface{} `json:"headers,omitempty"`
}

// parseFlowConfig parses flow configuration from request/response parameters.
func (p *LogMessagePolicy) parseFlowConfig(params map[string]interface{}, flowName string) flowConfig {
	cfg := flowConfig{
		excludedHeaders: map[string]struct{}{},
	}

	flowRaw, found := params[flowName]
	if !found || flowRaw == nil {
		return cfg
	}

	flow, ok := flowRaw.(map[string]interface{})
	if !ok {
		return cfg
	}

	cfg.logPayload = p.parseBool(flow["payload"])
	cfg.logHeaders = p.parseBool(flow["headers"])
	cfg.excludedHeaders = p.parseExcludedHeaders(flow["excludeHeaders"])
	return cfg
}

func (p *LogMessagePolicy) parseBool(raw interface{}) bool {
	parsed, _ := raw.(bool)
	return parsed
}

// parseExcludedHeaders parses a list of excluded header names.
func (p *LogMessagePolicy) parseExcludedHeaders(excludedHeadersRaw interface{}) map[string]struct{} {
	excludedHeaders := make(map[string]struct{})

	if excludedHeadersRaw == nil {
		return excludedHeaders
	}

	switch headers := excludedHeadersRaw.(type) {
	case []interface{}:
		for _, headerRaw := range headers {
			header, ok := headerRaw.(string)
			if !ok {
				continue
			}
			trimmed := strings.ToLower(strings.TrimSpace(header))
			if trimmed != "" {
				excludedHeaders[trimmed] = struct{}{}
			}
		}
	case []string:
		for _, header := range headers {
			trimmed := strings.ToLower(strings.TrimSpace(header))
			if trimmed != "" {
				excludedHeaders[trimmed] = struct{}{}
			}
		}
	}

	return excludedHeaders
}

// logMessage logs the structured log record using slog at INFO level
func (p *LogMessagePolicy) logMessage(record LogRecord) {
	logData, err := json.Marshal(record)
	if err != nil {
		slog.Error("Failed to marshal log record", "error", err)
		return
	}

	slog.Info(string(logData))
}

// OnRequestHeaders logs request headers in the header phase.
func (p *LogMessagePolicy) OnRequestHeaders(ctx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	config := p.parseFlowConfig(params, "request")

	if !config.logHeaders {
		return policy.UpstreamRequestHeaderModifications{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(ctx.Headers),
		HTTPMethod:    ctx.Method,
		ResourcePath:  ctx.Path,
		Headers:       p.buildHeadersMap(ctx.Headers, config.excludedHeaders),
	}

	p.logMessage(logRecord)

	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders logs response headers in the header phase.
func (p *LogMessagePolicy) OnResponseHeaders(ctx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	config := p.parseFlowConfig(params, "response")

	if !config.logHeaders {
		return policy.DownstreamResponseHeaderModifications{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestID(ctx.ResponseHeaders),
		HTTPMethod:    ctx.RequestMethod,
		ResourcePath:  ctx.RequestPath,
		Headers:       p.buildHeadersMap(ctx.ResponseHeaders, config.excludedHeaders),
	}

	p.logMessage(logRecord)

	return policy.DownstreamResponseHeaderModifications{}
}

// OnRequestBody logs the request payload.
// Header logging is handled by OnRequestHeaders.
func (p *LogMessagePolicy) OnRequestBody(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	config := p.parseFlowConfig(params, "request")

	// Skip logging if payload logging is disabled.
	if !config.logPayload {
		return policy.UpstreamRequestModifications{}
	}

	// Create log record
	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(ctx.Headers),
		HTTPMethod:    ctx.Method,
		ResourcePath:  ctx.Path,
	}

	// Log payload if present.
	if ctx.Body != nil && ctx.Body.Present && len(ctx.Body.Content) > 0 {
		logRecord.Payload = string(ctx.Body.Content)
	}

	// Log the message.
	p.logMessage(logRecord)

	// Continue with the request unchanged.
	return policy.UpstreamRequestModifications{}
}

// OnResponseBody logs the response payload.
// Header logging is handled by OnResponseHeaders.
func (p *LogMessagePolicy) OnResponseBody(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	config := p.parseFlowConfig(params, "response")

	// Skip logging if payload logging is disabled.
	if !config.logPayload {
		return policy.DownstreamResponseModifications{}
	}

	// Create log record
	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestID(ctx.ResponseHeaders),
		HTTPMethod:    ctx.RequestMethod,
		ResourcePath:  ctx.RequestPath,
	}

	// Log payload if present.
	if ctx.ResponseBody != nil && ctx.ResponseBody.Present && len(ctx.ResponseBody.Content) > 0 {
		logRecord.Payload = string(ctx.ResponseBody.Content)
	}

	// Log the message.
	p.logMessage(logRecord)

	// Continue with the response unchanged.
	return policy.DownstreamResponseModifications{}
}

// ─── Streaming (SSE) support ──────────────────────────────────────────────────
//
// Log-message is a read-only side-effect policy — it never modifies payloads
// or blocks the request/response flow. This makes it one of the safest and
// most natural streaming candidates: each chunk is logged as it passes through,
// providing real-time observability into streaming LLM responses without adding
// latency or requiring accumulation.
//
// NeedsMoreRequestData and NeedsMoreResponseData always return false because
// there is no accumulation requirement — individual chunks can be logged
// independently as soon as they arrive.

// NeedsMoreRequestData implements StreamingRequestPolicy.
// Always returns false — each request chunk is logged independently.
func (p *LogMessagePolicy) NeedsMoreRequestData(accumulated []byte) bool {
	return false
}

// OnRequestBodyChunk implements StreamingRequestPolicy.
// Logs each streaming request chunk as it arrives. The full request body is
// logged incrementally across chunks rather than buffered into a single record.
func (p *LogMessagePolicy) OnRequestBodyChunk(ctx *policy.RequestStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.RequestChunkAction {
	config := p.parseFlowConfig(params, "request")
	if !config.logPayload || chunk == nil || len(chunk.Chunk) == 0 {
		return policy.RequestChunkAction{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(ctx.Headers),
		HTTPMethod:    ctx.Method,
		ResourcePath:  ctx.Path,
		Payload:       string(chunk.Chunk),
	}
	p.logMessage(logRecord)

	return policy.RequestChunkAction{}
}

// NeedsMoreResponseData implements StreamingResponsePolicy.
// Always returns false — each response chunk is logged independently.
func (p *LogMessagePolicy) NeedsMoreResponseData(accumulated []byte) bool {
	return false
}

// OnResponseBodyChunk implements StreamingResponsePolicy.
// Logs each streaming response chunk as it arrives, providing real-time
// visibility into SSE token streams without buffering or latency overhead.
func (p *LogMessagePolicy) OnResponseBodyChunk(ctx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.ResponseChunkAction {
	config := p.parseFlowConfig(params, "response")
	if !config.logPayload || chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ResponseChunkAction{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestID(ctx.ResponseHeaders),
		HTTPMethod:    ctx.RequestMethod,
		ResourcePath:  ctx.RequestPath,
		Payload:       string(chunk.Chunk),
	}
	p.logMessage(logRecord)

	return policy.ResponseChunkAction{}
}

// getRequestID extracts request ID from request headers
func (p *LogMessagePolicy) getRequestID(headers *policy.Headers) string {
	if headers == nil {
		return ErrMsgMissingReqID
	}
	if requestIDs := headers.Get(HeaderXRequestID); len(requestIDs) > 0 {
		return requestIDs[0]
	}
	return ErrMsgMissingReqID
}

// getResponseRequestID extracts request ID from response headers
func (p *LogMessagePolicy) getResponseRequestID(headers *policy.Headers) string {
	if headers == nil {
		return ErrMsgMissingReqID
	}
	if requestIDs := headers.Get(HeaderXRequestID); len(requestIDs) > 0 {
		return requestIDs[0]
	}
	return ErrMsgMissingReqID
}

// buildHeadersMap builds a map of headers for logging, excluding sensitive ones
func (p *LogMessagePolicy) buildHeadersMap(headers *policy.Headers, excludedHeaders map[string]struct{}) map[string]interface{} {
	headersMap := make(map[string]interface{})
	if headers == nil {
		return headersMap
	}

	headers.Iterate(func(name string, values []string) {
		lowerName := strings.ToLower(name)

		// Skip excluded headers
		if _, excluded := excludedHeaders[lowerName]; excluded {
			return // continue iteration
		}

		// Mask authorization header by default
		if lowerName == "authorization" {
			headersMap[name] = "***"
			return
		}

		// Add header to map
		if len(values) == 1 {
			headersMap[name] = values[0]
		} else {
			headersMap[name] = values
		}
	})

	return headersMap
}
