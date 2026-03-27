/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package cors

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

type CorsPolicy struct {
	AllowedOrigins         []string
	CompiledAllowedOrigins []*regexp.Regexp
	AllowedMethods         []string
	AllowedHeaders         []string
	ExposedHeaders         []string
	MaxAge                 *int
	AllowCredentials       *bool
	ForwardPreflight       bool
}

// GetPolicy is the v1alpha factory entry point (loaded by v1alpha kernels).
// The returned concrete type also satisfies policyv1alpha2 phase interfaces
// (StreamingResponsePolicy, RequestPolicy, ResponsePolicy), so v1alpha2 kernels
// can discover those capabilities via type assertions even when using this factory.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]any,
) (policy.Policy, error) {
	slog.Debug("Cors Policy: GetPolicy called")
	p := &CorsPolicy{}
	p.AllowedOrigins = getStringArrayParam(params, "allowedOrigins", []string{"*"})
	if slices.Contains(p.AllowedOrigins, "*") {
		slog.Debug("Ignoring other origins as wildcard is included")
		p.AllowedOrigins = []string{"*"}
	}
	p.AllowedMethods = getStringArrayParam(params, "allowedMethods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	p.AllowedHeaders = getStringArrayParam(params, "allowedHeaders", []string{})
	if slices.Contains(p.AllowedHeaders, "*") {
		slog.Debug("Ignoring other headers as wildcard is included")
		p.AllowedHeaders = []string{"*"}
	}
	p.ExposedHeaders = getStringArrayParam(params, "exposedHeaders", nil)

	if v, ok := params["maxAge"]; ok {
		if i, ok := v.(int); ok {
			val := i
			p.MaxAge = &val
		} else if f, ok := v.(float64); ok {
			val := int(f)
			p.MaxAge = &val
		}
	}

	val, ok := params["allowCredentials"]
	if ok {
		if b, ok := val.(bool); ok {
			p.AllowCredentials = &b
		}
	}

	if p.AllowCredentials != nil && *p.AllowCredentials {
		// As per CORS spec, wildcard cannot be used with allow-credentials
		if len(p.AllowedOrigins) == 1 && p.AllowedOrigins[0] == "*" {
			slog.Debug("Cannot have wildcard origin with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard origin with allowCredentials set to true")
		} else if len(p.AllowedHeaders) == 1 && p.AllowedHeaders[0] == "*" {
			slog.Debug("Cannot have wildcard headers with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard headers with allowCredentials set to true")
		} else if len(p.AllowedMethods) == 1 && p.AllowedMethods[0] == "*" {
			slog.Debug("Cannot have wildcard methods with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard methods with allowCredentials set to true")
		} else if len(p.ExposedHeaders) == 1 && p.ExposedHeaders[0] == "*" {
			slog.Debug("Cannot have wildcard exposed headers with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard exposed headers with allowCredentials set to true")
		}
	}

	val, ok = params["forwardPreflight"]
	if ok {
		if b, ok := val.(bool); ok {
			p.ForwardPreflight = b
		}
	} else {
		p.ForwardPreflight = false
	}

	for _, origin := range p.AllowedOrigins {
		if origin == "*" {
			continue
		}
		regex, err := regexp.Compile(origin)
		if err != nil {
			slog.Debug("Invalid origin regex", "origin", origin, "error", err)
			return nil, fmt.Errorf("invalid origin regex: %s", origin)
		}
		p.CompiledAllowedOrigins = append(p.CompiledAllowedOrigins, regex)
	}

	return p, nil
}

// GetPolicyV2 is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicyV2(
	metadata policyv1alpha2.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha2.Policy, error) {
	return GetPolicy(policy.PolicyMetadata{
		RouteName:  metadata.RouteName,
		APIId:      metadata.APIId,
		APIName:    metadata.APIName,
		APIVersion: metadata.APIVersion,
		AttachedTo: policy.Level(metadata.AttachedTo),
	}, params)
}

func (p *CorsPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func (p *CorsPolicy) OnRequest(ctx *policy.RequestContext, params map[string]any) policy.RequestAction {
	if strings.EqualFold(ctx.Method, "options") {
		slog.Debug("CORS: Preflight request detected; handling preflight")
		return p.handlePreflight(ctx)
	} else {
		// Non-preflight
		corsHeaders, ok := p.handleNonPreflight(ctx)
		if ok {
			slog.Debug("CORS: Adding CORS headers to non-preflight request")
			ctx.Metadata["cors_headers"] = corsHeaders
		} else {
			slog.Debug("CORS: No CORS headers to add for non-preflight request")
			// If there was an Origin header, we must strip any CORS headers
			// that the upstream may have set, to prevent origin bypass
			if ctx.Headers.Has("Origin") {
				ctx.Metadata["cors_strip"] = true
			}
		}
		return nil
	}
}

// handlePreflight processes CORS preflight (OPTIONS) requests
func (p *CorsPolicy) handlePreflight(ctx *policy.RequestContext) policy.RequestAction {
	requestHeaders := ctx.Headers
	origin := requestHeaders.Get("Origin")

	isCorsFailure := false
	headers := make(map[string]string)

	requestedMethod := requestHeaders.Get("Access-Control-Request-Method")
	requestedHeaders := requestHeaders.Get("Access-Control-Request-Headers")

	// handle origins
	originAllowed := false
	if len(p.AllowedOrigins) > 0 {
		if p.AllowedOrigins[0] == "*" {
			slog.Debug("CORS: Allowing all origins")
			headers["Access-Control-Allow-Origin"] = "*"
			originAllowed = true
		} else if len(origin) > 0 {
			for _, regex := range p.CompiledAllowedOrigins {
				if regex.MatchString(origin[0]) {
					slog.Debug("CORS: Adding allowed origins")
					headers["Access-Control-Allow-Origin"] = origin[0]
					originAllowed = true
					break
				}
			}
		}
	}
	if !originAllowed {
		slog.Debug("CORS: Origin not allowed")
		isCorsFailure = true
	}

	// handle methods
	methodAllowed := false
	if len(p.AllowedMethods) > 0 {
		if p.AllowedMethods[0] == "*" {
			slog.Debug("CORS: Allowing all methods")
			headers["Access-Control-Allow-Methods"] = "*"
			methodAllowed = true
		} else if len(requestedMethod) > 0 {
			if slices.Contains(p.AllowedMethods, requestedMethod[0]) {
				slog.Debug("CORS: Adding allowed methods")
				headers["Access-Control-Allow-Methods"] = strings.Join(p.AllowedMethods, ",")
				methodAllowed = true
			}
		}
	}
	if !methodAllowed {
		slog.Debug("CORS: Method not allowed")
		isCorsFailure = true
	}

	// handle headers
	headersAllowed := false
	if len(p.AllowedHeaders) > 0 {
		if p.AllowedHeaders[0] == "*" {
			slog.Debug("CORS: Allowing all headers")
			if len(requestedHeaders) > 0 {
				headers["Access-Control-Allow-Headers"] = requestedHeaders[0]
			}
			headersAllowed = true
		} else if len(requestedHeaders) > 0 {
			var checkedHeaders []string
			requestedList := strings.Split(requestedHeaders[0], ",")
			allowedCount := 0
			for _, allowedHeader := range p.AllowedHeaders {
				for _, requestedHeader := range requestedList {
					if strings.EqualFold(strings.TrimSpace(allowedHeader), strings.TrimSpace(requestedHeader)) {
						checkedHeaders = append(checkedHeaders, allowedHeader)
						allowedCount++
					}
				}
			}
			if len(requestedList) == allowedCount {
				slog.Debug("CORS: Adding allowed headers")
				headers["Access-Control-Allow-Headers"] = strings.Join(checkedHeaders, ",")
				headersAllowed = true
			}
		}
	}

	if !headersAllowed && len(requestedHeaders) > 0 {
		slog.Debug("CORS: Headers not allowed")
		isCorsFailure = true
	}

	if p.MaxAge != nil {
		slog.Debug("CORS: Adding max age header")
		headers["Access-Control-Max-Age"] = fmt.Sprintf("%d", *p.MaxAge)
	}

	if p.AllowCredentials != nil {
		slog.Debug("CORS: Adding allow credentials header")
		headers["Access-Control-Allow-Credentials"] = fmt.Sprintf("%t", *p.AllowCredentials)
	}

	if isCorsFailure {
		slog.Debug("CORS: Preflight request did not pass the conditions")
		headers = make(map[string]string)
		if p.ForwardPreflight {
			slog.Debug("CORS: Forwarding preflight request to upstream.")
			return policy.UpstreamRequestModifications{}
		}
	}

	return policy.ImmediateResponse{
		StatusCode: 204,
		Headers:    headers,
		Body:       nil,
	}
}

func (p *CorsPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]any) policy.ResponseAction {
	corsHeaders, ok := ctx.Metadata["cors_headers"].(map[string]string)
	if ok {
		slog.Debug("CORS: Adding CORS headers to response")
		return policy.UpstreamResponseModifications{
			SetHeaders: corsHeaders,
		}
	}
	if _, strip := ctx.Metadata["cors_strip"]; strip {
		slog.Debug("CORS: Stripping upstream CORS headers for disallowed origin")
		return policy.UpstreamResponseModifications{
			RemoveHeaders: []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Credentials",
				"Access-Control-Expose-Headers",
			},
		}
	}
	slog.Debug("CORS: No CORS headers to add to response")
	return nil
}

// handleNonPreflight adds CORS headers to actual (non-preflight) responses
func (p *CorsPolicy) handleNonPreflight(ctx *policy.RequestContext) (map[string]string, bool) {
	// Add CORS headers for actual requests
	headersToInclude := make(map[string]string)

	requestHeaders := ctx.Headers
	origin := requestHeaders.Get("Origin")

	// Handle allowed origin
	originAllowed := false
	if len(p.AllowedOrigins) > 0 {
		if p.AllowedOrigins[0] == "*" {
			headersToInclude["Access-Control-Allow-Origin"] = "*"
			originAllowed = true
		} else if len(origin) > 0 {
			for _, regex := range p.CompiledAllowedOrigins {
				if regex.MatchString(origin[0]) {
					headersToInclude["Access-Control-Allow-Origin"] = origin[0]
					// Advise caches that response may vary by Origin
					headersToInclude["Vary"] = "Origin"
					originAllowed = true
					break
				}
			}
		}
	}

	if !originAllowed {
		slog.Debug("CORS: Origin not allowed for non-preflight request")
		return nil, false
	}

	// Expose headers to the client, if configured
	if len(p.ExposedHeaders) > 0 {
		slog.Debug("CORS: Adding exposed headers")
		headersToInclude["Access-Control-Expose-Headers"] = strings.Join(p.ExposedHeaders, ",")
	}

	// Allow credentials if enabled
	if p.AllowCredentials != nil {
		slog.Debug("CORS: Adding allow credentials header")
		headersToInclude["Access-Control-Allow-Credentials"] = fmt.Sprintf("%t", *p.AllowCredentials)
	}

	return headersToInclude, true
}

func getStringArrayParam(params map[string]any, key string, defaultValue []string) []string {
	if v, ok := params[key]; ok {
		if arr, ok := v.([]any); ok {
			var result []string
			for _, item := range arr {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}
	return defaultValue
}

// OnRequestHeaders handles CORS in the request header phase.
func (p *CorsPolicy) OnRequestHeaders(ctx *policyv1alpha2.RequestHeaderContext, params map[string]any) policyv1alpha2.RequestHeaderAction {
	if strings.EqualFold(ctx.Method, "options") {
		slog.Debug("CORS: Preflight request detected in header phase; handling preflight")
		return p.handlePreflightHeaders(ctx.Headers)
	}
	corsHeaders, ok := p.handleNonPreflightHeaders(ctx.Headers)
	if ok {
		slog.Debug("CORS: Adding CORS headers to non-preflight request")
		ctx.Metadata["cors_headers"] = corsHeaders
	} else {
		slog.Debug("CORS: No CORS headers to add for non-preflight request")
		if ctx.Headers.Has("Origin") {
			ctx.Metadata["cors_strip"] = true
		}
	}
	return policyv1alpha2.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders sets CORS headers on the response in the header phase.
func (p *CorsPolicy) OnResponseHeaders(ctx *policyv1alpha2.ResponseHeaderContext, params map[string]any) policyv1alpha2.ResponseHeaderAction {
	corsHeaders, ok := ctx.Metadata["cors_headers"].(map[string]string)
	if ok {
		slog.Debug("CORS: Adding CORS headers to response in header phase")
		return policyv1alpha2.DownstreamResponseHeaderModifications{
			HeadersToSet: corsHeaders,
		}
	}
	if _, strip := ctx.Metadata["cors_strip"]; strip {
		slog.Debug("CORS: Stripping upstream CORS headers for disallowed origin in header phase")
		return policyv1alpha2.DownstreamResponseHeaderModifications{
			HeadersToRemove: []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Credentials",
				"Access-Control-Expose-Headers",
			},
		}
	}
	slog.Debug("CORS: No CORS headers to add to response in header phase")
	return policyv1alpha2.DownstreamResponseHeaderModifications{}
}

// handlePreflightHeaders processes CORS preflight (OPTIONS) requests using raw headers.
func (p *CorsPolicy) handlePreflightHeaders(requestHeaders *policyv1alpha2.Headers) policyv1alpha2.RequestHeaderAction {
	origin := requestHeaders.Get("Origin")

	isCorsFailure := false
	headers := make(map[string]string)

	requestedMethod := requestHeaders.Get("Access-Control-Request-Method")
	requestedHeaders := requestHeaders.Get("Access-Control-Request-Headers")

	originAllowed := false
	if len(p.AllowedOrigins) > 0 {
		if p.AllowedOrigins[0] == "*" {
			headers["Access-Control-Allow-Origin"] = "*"
			originAllowed = true
		} else if len(origin) > 0 {
			for _, regex := range p.CompiledAllowedOrigins {
				if regex.MatchString(origin[0]) {
					headers["Access-Control-Allow-Origin"] = origin[0]
					originAllowed = true
					break
				}
			}
		}
	}
	if !originAllowed {
		isCorsFailure = true
	}

	methodAllowed := false
	if len(p.AllowedMethods) > 0 {
		if p.AllowedMethods[0] == "*" {
			headers["Access-Control-Allow-Methods"] = "*"
			methodAllowed = true
		} else if len(requestedMethod) > 0 {
			if slices.Contains(p.AllowedMethods, requestedMethod[0]) {
				headers["Access-Control-Allow-Methods"] = strings.Join(p.AllowedMethods, ",")
				methodAllowed = true
			}
		}
	}
	if !methodAllowed {
		isCorsFailure = true
	}

	headersAllowed := false
	if len(p.AllowedHeaders) > 0 {
		if p.AllowedHeaders[0] == "*" {
			if len(requestedHeaders) > 0 {
				headers["Access-Control-Allow-Headers"] = requestedHeaders[0]
			}
			headersAllowed = true
		} else if len(requestedHeaders) > 0 {
			var checkedHeaders []string
			requestedList := strings.Split(requestedHeaders[0], ",")
			allowedCount := 0
			for _, allowedHeader := range p.AllowedHeaders {
				for _, requestedHeader := range requestedList {
					if strings.EqualFold(strings.TrimSpace(allowedHeader), strings.TrimSpace(requestedHeader)) {
						checkedHeaders = append(checkedHeaders, allowedHeader)
						allowedCount++
					}
				}
			}
			if len(requestedList) == allowedCount {
				headers["Access-Control-Allow-Headers"] = strings.Join(checkedHeaders, ",")
				headersAllowed = true
			}
		}
	}

	if !headersAllowed && len(requestedHeaders) > 0 {
		isCorsFailure = true
	}

	if p.MaxAge != nil {
		headers["Access-Control-Max-Age"] = fmt.Sprintf("%d", *p.MaxAge)
	}

	if p.AllowCredentials != nil {
		headers["Access-Control-Allow-Credentials"] = fmt.Sprintf("%t", *p.AllowCredentials)
	}

	if isCorsFailure {
		headers = make(map[string]string)
		if p.ForwardPreflight {
			return policyv1alpha2.UpstreamRequestHeaderModifications{}
		}
	}

	return policyv1alpha2.ImmediateResponse{
		StatusCode: 204,
		Headers:    headers,
		Body:       nil,
	}
}

// handleNonPreflightHeaders adds CORS headers for actual (non-preflight) requests using raw headers.
func (p *CorsPolicy) handleNonPreflightHeaders(requestHeaders *policyv1alpha2.Headers) (map[string]string, bool) {
	headersToInclude := make(map[string]string)

	origin := requestHeaders.Get("Origin")

	originAllowed := false
	if len(p.AllowedOrigins) > 0 {
		if p.AllowedOrigins[0] == "*" {
			headersToInclude["Access-Control-Allow-Origin"] = "*"
			originAllowed = true
		} else if len(origin) > 0 {
			for _, regex := range p.CompiledAllowedOrigins {
				if regex.MatchString(origin[0]) {
					headersToInclude["Access-Control-Allow-Origin"] = origin[0]
					headersToInclude["Vary"] = "Origin"
					originAllowed = true
					break
				}
			}
		}
	}

	if !originAllowed {
		return nil, false
	}

	if len(p.ExposedHeaders) > 0 {
		headersToInclude["Access-Control-Expose-Headers"] = strings.Join(p.ExposedHeaders, ",")
	}

	if p.AllowCredentials != nil {
		headersToInclude["Access-Control-Allow-Credentials"] = fmt.Sprintf("%t", *p.AllowCredentials)
	}

	return headersToInclude, true
}
