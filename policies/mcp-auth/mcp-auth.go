/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package mcpauthn

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	jwtauth "github.com/wso2/gateway-controllers/policies/jwt-auth"
)

const (
	WWWAuthenticateHeader  = "WWW-Authenticate"
	AuthMethodBearer       = "Bearer resource_metadata="
	WellKnownPath          = ".well-known/oauth-protected-resource"
	WellKnownEndpointPath  = "/" + WellKnownPath
	McpSessionHeader       = "mcp-session-id"
	AuthType               = "mcp/oauth"
	MetadataKeyAuthSuccess = "auth.success"
	MetadataKeyAuthMethod  = "auth.method"
)

type McpAuthPolicy struct {
	AuthConfig          McpAuthConfig `json:"authConfig"`
	Issuers             []string      `json:"issuers"`
	RequiredScopes      []string      `json:"requiredScopes"`
	OnFailureStatusCode int           `json:"onFailureStatusCode"`
	ErrorMessageFormat  string        `json:"errorMessageFormat"`
	GatewayHost         string        `json:"gatewayHost"`
}

type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// SecurityConfig represents the configuration for tools, resources, prompts, or methods
type SecurityConfig struct {
	Enabled    bool     `json:"enabled"`
	Exceptions []string `json:"exceptions"`
}

// McpAuthConfig holds the parsed MCP auth configuration
type McpAuthConfig struct {
	Tools     SecurityConfig
	Resources SecurityConfig
	Prompts   SecurityConfig
	Methods   SecurityConfig
}

// MCPRequest represents the JSON-RPC MCP request structure
type MCPRequest struct {
	Method string           `json:"method"`
	Params MCPRequestParams `json:"params"`
}

// MCPRequestParams represents the params section of an MCP request
// Different MCP methods use different param structures:
// - tools/call: uses "name" (tool name) and "arguments"
// - resources/read: uses "uri" (resource URI)
// - prompts/get: uses "name" (prompt name)
type MCPRequestParams struct {
	Name      string         `json:"name"` // For tools/call, prompts/get
	Arguments map[string]any `json:"arguments"`
	URI       string         `json:"uri"` // For resources/read
}

// GetPolicyV2 is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicyV2(
	metadata policyv1alpha2.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha2.Policy, error) {
	slog.Debug("MCP Auth Policy: GetPolicyV2 called")
	ins := &McpAuthPolicy{
		AuthConfig: GetMcpAuthConfig(params),
	}
	ins.Issuers = getStringArrayParam(params, "issuers", []string{})
	ins.RequiredScopes = getStringArrayParam(params, "requiredScopes", []string{})
	ins.OnFailureStatusCode = getIntParam(params, "onFailureStatusCode", 401)
	ins.ErrorMessageFormat = getStringParam(params, "errorMessageFormat", "json")
	ins.GatewayHost = getStringParam(params, "gatewayHost", "")

	return ins, nil
}

func (p *McpAuthPolicy) Mode() policyv1alpha2.ProcessingMode {
	return policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeSkip,
		RequestBodyMode:    policyv1alpha2.BodyModeBuffer,
		ResponseHeaderMode: policyv1alpha2.HeaderModeSkip,
		ResponseBodyMode:   policyv1alpha2.BodyModeSkip,
	}
}

// parseAuthority extracts host and port from an authority string (e.g., "example.com:8080")
func parseAuthority(authority string) (host string, port int) {
	if authority == "" {
		return "", -1
	}
	hostPort := strings.SplitN(authority, ":", 2)
	host = hostPort[0]
	if len(hostPort) > 1 {
		port, _ = strconv.Atoi(hostPort[1])
	} else {
		port = -1
	}
	return host, port
}

// isStandardPort returns true if the port is the standard port for the given scheme
func isStandardPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

func getStringParam(params map[string]interface{}, key, defaultValue string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultValue
}

func getIntParam(params map[string]interface{}, key string, defaultValue int) int {
	if v, ok := params[key]; ok {
		if i, ok := v.(int); ok {
			return i
		}
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return defaultValue
}

func getStringArrayParam(params map[string]interface{}, key string, defaultValue []string) []string {
	if v, ok := params[key]; ok {
		if arr, ok := v.([]interface{}); ok {
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

// getSecurityConfigParam parses a security configuration object (tools, resources, prompts, methods)
// with enabled (default: true) and exceptions (default: empty array) fields.
func getSecurityConfigParam(params map[string]any, key string) SecurityConfig {
	config := SecurityConfig{
		Enabled:    true, // default value per policy definition
		Exceptions: []string{},
	}

	if v, ok := params[key]; ok {
		if configMap, ok := v.(map[string]any); ok {
			// Parse enabled field
			if enabled, ok := configMap["enabled"]; ok {
				if b, ok := enabled.(bool); ok {
					config.Enabled = b
					slog.Debug("MCP Auth Policy", "key", key, "enabled", b)
				}
			}
			// Parse exceptions field
			if exceptions, ok := configMap["exceptions"]; ok {
				if arr, ok := exceptions.([]any); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							config.Exceptions = append(config.Exceptions, s)
						}
					}
					slog.Debug("MCP Auth Policy", "key", key, "exceptions", len(config.Exceptions))
				}
			}
		}
	} else {
		slog.Debug("MCP Auth Policy: No configuration found for key", "key", key)
	}

	return config
}

// GetMcpAuthConfig parses all MCP auth configuration parameters into a structured format.
func GetMcpAuthConfig(params map[string]any) McpAuthConfig {
	return McpAuthConfig{
		Tools:     getSecurityConfigParam(params, "tools"),
		Resources: getSecurityConfigParam(params, "resources"),
		Prompts:   getSecurityConfigParam(params, "prompts"),
		Methods:   getSecurityConfigParam(params, "methods"),
	}
}

// isAuthRequired determines if authentication is required for the given MCP request.
// It returns true if auth is required, false if the request is exempt based on configuration.
func (p *McpAuthPolicy) isAuthRequired(mcpReq MCPRequest) bool {
	var config SecurityConfig
	var name string

	switch mcpReq.Method {
	case "tools/call":
		config = p.AuthConfig.Tools
		name = mcpReq.Params.Name
	case "resources/read":
		config = p.AuthConfig.Resources
		name = mcpReq.Params.URI
	case "prompts/get":
		config = p.AuthConfig.Prompts
		name = mcpReq.Params.Name
	default:
		// For any other methods (e.g., "initialize", "ping", "tools/list", etc.)
		// Check if the method is in the methods exceptions list
		config = p.AuthConfig.Methods
		name = mcpReq.Method
	}

	if config.Enabled {
		if len(config.Exceptions) == 0 {
			return true
		} else {
			for _, exception := range config.Exceptions {
				if exception == name {
					slog.Debug("MCP Auth Policy: Auth not required - item in exceptions list", "method", mcpReq.Method, "name", name)
					return false
				}
			}
			return true
		}
	} else {
		if len(config.Exceptions) == 0 {
			return false
		} else {
			for _, exception := range config.Exceptions {
				if exception == name {
					slog.Debug("MCP Auth Policy: Auth required - item in exceptions list", "method", mcpReq.Method, "name", name)
					return true
				}
			}
			return false
		}
	}
}

// Helper functions for type assertions
func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func parseKeyManagers(keyManagersRaw any) ([]string, map[string]string, error) {
	keyManagersList, ok := keyManagersRaw.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("invalid policy configuration: keyManagers must be an array")
	}

	issuers := make([]string, 0, len(keyManagersList))
	keyManagers := make(map[string]string, len(keyManagersList))
	for _, km := range keyManagersList {
		kmMap, ok := km.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("invalid policy configuration: keyManagers entries must be objects")
		}

		name := strings.TrimSpace(getString(kmMap["name"]))
		issuer := strings.TrimSpace(getString(kmMap["issuer"]))
		if name == "" || issuer == "" {
			return nil, nil, fmt.Errorf("invalid policy configuration: each keyManager requires non-empty name and issuer")
		}

		issuers = append(issuers, issuer)
		keyManagers[name] = issuer
	}

	return issuers, keyManagers, nil
}

func isWellKnownEndpointRequest(path string) bool {
	return path == WellKnownEndpointPath || strings.HasSuffix(path, WellKnownEndpointPath)
}

func validateAuthFailureConfig(statusCode int, format string) error {
	if statusCode != 401 && statusCode != 403 {
		return fmt.Errorf("invalid policy configuration: onFailureStatusCode must be 401 or 403")
	}

	switch format {
	case "json", "plain", "minimal":
		return nil
	default:
		return fmt.Errorf("invalid policy configuration: errorMessageFormat must be one of [json, plain, minimal]")
	}
}

func buildInvalidConfigResponseV2(message string) policyv1alpha2.RequestAction {
	body, _ := json.Marshal(map[string]string{
		"error":   "Internal Server Error",
		"message": message,
	})
	return policyv1alpha2.ImmediateResponse{
		StatusCode: 500,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body: body,
	}
}

func ensureRequestMetadataV2(ctx *policyv1alpha2.RequestContext) {
	if ctx.SharedContext == nil {
		ctx.SharedContext = &policyv1alpha2.SharedContext{}
	}
	if ctx.Metadata == nil {
		ctx.Metadata = map[string]any{}
	}
}

func (p *McpAuthPolicy) OnRequestHeaders(ctx *policyv1alpha2.RequestHeaderContext, params map[string]interface{}) policyv1alpha2.RequestHeaderAction {
	if err := validateAuthFailureConfig(p.OnFailureStatusCode, p.ErrorMessageFormat); err != nil {
		v1r := buildInvalidConfigResponseV2(err.Error()).(policyv1alpha2.ImmediateResponse)
		return policyv1alpha2.ImmediateResponse{StatusCode: v1r.StatusCode, Headers: v1r.Headers, Body: v1r.Body}
	}
	// Check for GET /.well-known/oauth-protected-resource
	if ctx.Method == "GET" && isWellKnownEndpointRequest(ctx.OperationPath) {
		slog.Debug("MCP Auth Policy: Handling well-known protected resource metadata request")
		sessionIds := ctx.Headers.Get(McpSessionHeader)
		sessionId := ""
		if len(sessionIds) > 0 {
			sessionId = sessionIds[0]
		}

		keyManagersRaw, ok := params["keyManagers"]
		if !ok {
			slog.Debug("MCP Auth Policy: Key managers not configured in params")
			return p.handleAuthFailureV2(ctx.SharedContext, p.OnFailureStatusCode, p.ErrorMessageFormat, "key managers not configured")
		}

		slog.Debug("MCP Auth Policy: Starting to parse key managers configuration")
		issuers, kms, err := parseKeyManagers(keyManagersRaw)
		if err != nil {
			v1r := buildInvalidConfigResponseV2(err.Error()).(policyv1alpha2.ImmediateResponse)
			return policyv1alpha2.ImmediateResponse{StatusCode: v1r.StatusCode, Headers: v1r.Headers, Body: v1r.Body}
		}
		if len(issuers) == 0 {
			return p.handleAuthFailureV2(ctx.SharedContext, p.OnFailureStatusCode, p.ErrorMessageFormat, "no valid key managers found")
		}

		if len(p.Issuers) > 0 {
			filteredIssuers := []string{}
			for _, ui := range p.Issuers {
				if issuer, ok := kms[ui]; ok {
					filteredIssuers = append(filteredIssuers, issuer)
					slog.Debug("MCP Auth Policy: Added issuer from user configuration", "issuer", issuer)
				}
			}
			issuers = filteredIssuers
		}

		if len(issuers) == 0 {
			return p.handleAuthFailureV2(ctx.SharedContext, p.OnFailureStatusCode, p.ErrorMessageFormat, "no matching issuers found")
		}

		prm := ProtectedResourceMetadata{
			Resource:             generateResourcePathFromFields(ctx.Scheme, ctx.Authority, ctx.Vhost, ctx.APIContext, params, "mcp"),
			AuthorizationServers: issuers,
			ScopesSupported:      p.RequiredScopes,
		}
		jsonOut, _ := json.Marshal(prm)
		return policyv1alpha2.ImmediateResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type":   "application/json",
				McpSessionHeader: sessionId,
			},
			Body: jsonOut,
		}
	}
	return policyv1alpha2.UpstreamRequestHeaderModifications{}
}

// OnRequestBody processes the request body phase for MCP authentication.
func (p *McpAuthPolicy) OnRequestBody(ctx *policyv1alpha2.RequestContext, params map[string]any) policyv1alpha2.RequestAction {
	if err := validateAuthFailureConfig(p.OnFailureStatusCode, p.ErrorMessageFormat); err != nil {
		v1r := buildInvalidConfigResponseV2(err.Error()).(policyv1alpha2.ImmediateResponse)
		return policyv1alpha2.ImmediateResponse{StatusCode: v1r.StatusCode, Headers: v1r.Headers, Body: v1r.Body}
	}

	if p.GatewayHost != "" {
		ensureRequestMetadataV2(ctx)
		ctx.Metadata["gatewayHost"] = p.GatewayHost
	}

	if ctx.Method == "POST" && strings.Contains(ctx.OperationPath, "mcp") {
		if ctx.Body == nil || !ctx.Body.Present {
			return p.handleAuthV2(ctx, params, p.RequiredScopes)
		}
		var mcpReq MCPRequest
		if err := json.Unmarshal(ctx.Body.Content, &mcpReq); err != nil {
			slog.Debug("MCP Auth Policy: Failed to parse MCP request", "error", err)
			return p.handleAuthFailureV2(ctx.SharedContext, p.OnFailureStatusCode, p.ErrorMessageFormat, "Invalid MCP request format")
		}

		slog.Debug("MCP Auth Policy: Extracted MCP attributes",
			"method", mcpReq.Method,
			"name", mcpReq.Params.Name,
			"uri", mcpReq.Params.URI)

		if !p.isAuthRequired(mcpReq) {
			slog.Debug("MCP Auth Policy: Skipping authentication for exempt request", "method", mcpReq.Method)
			return nil
		}

		return p.handleAuthV2(ctx, params, p.RequiredScopes)
	}

	return policyv1alpha2.UpstreamRequestModifications{}
}

// handleAuthFailureV2 constructs an authentication failure response.
func (p *McpAuthPolicy) handleAuthFailureV2(shared *policyv1alpha2.SharedContext, statusCode int, format string, reason any) policyv1alpha2.ImmediateResponse {
	shared.AuthContext = &policyv1alpha2.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]any{}
	}
	shared.Metadata[MetadataKeyAuthSuccess] = false
	shared.Metadata[MetadataKeyAuthMethod] = "mcpAuth"

	headers := map[string]string{"content-type": "application/json"}
	var body string
	switch format {
	case "plain":
		body = fmt.Sprintf("Authentication failed: %s", reason)
		headers["content-type"] = "text/plain"
	case "minimal":
		body = "Unauthorized"
	default:
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": fmt.Sprintf("MCP authentication failed: %s", reason),
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}
	return policyv1alpha2.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

// handleAuthV2 performs MCP authentication in the request body phase.
func (p *McpAuthPolicy) handleAuthV2(ctx *policyv1alpha2.RequestContext, params map[string]any, scopes []string) policyv1alpha2.RequestAction {
	type requestHeaderPolicer interface {
		OnRequestHeaders(*policyv1alpha2.RequestHeaderContext, map[string]interface{}) policyv1alpha2.RequestHeaderAction
	}

	sessionIds := ctx.Headers.Get(McpSessionHeader)
	sessionId := ""
	if len(sessionIds) > 0 {
		sessionId = sessionIds[0]
	}

	slog.Debug("MCP Auth Policy: Delegating authentication to JWT Auth Policy")
	jwtPolicy, err := jwtauth.GetPolicyV2(policyv1alpha2.PolicyMetadata{}, params)
	if err != nil {
		return p.handleAuthFailureV2(ctx.SharedContext, 500, "json", fmt.Sprintf("jwtauth.GetPolicy unavailable: %s", err))
	}
	hrp, ok := jwtPolicy.(requestHeaderPolicer)
	if !ok {
		return p.handleAuthFailureV2(ctx.SharedContext, 500, "json", "jwtPolicy does not implement OnRequestHeaders")
	}

	headerCtx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: ctx.SharedContext,
		Headers:       ctx.Headers,
		Path:          ctx.Path,
		Method:        ctx.Method,
		Authority:     ctx.Authority,
		Scheme:        ctx.Scheme,
		Vhost:         ctx.Vhost,
	}
	headerAction := hrp.OnRequestHeaders(headerCtx, params)
	if ir, ok := headerAction.(policyv1alpha2.ImmediateResponse); ok {
		slog.Debug("MCP Auth Policy: Authentication failed in JWT Auth Policy, handling failure")
		ctx.SharedContext.AuthContext = &policyv1alpha2.AuthContext{
			Authenticated: false,
			AuthType:      AuthType,
			Previous:      ctx.SharedContext.AuthContext,
		}
		headers := ir.Headers
		escapedDesc := ""
		if headers["content-type"] == "application/json" {
			var errResp map[string]any
			if err := json.Unmarshal(ir.Body, &errResp); err == nil {
				if errDesc, ok := errResp["message"].(string); ok {
					escapedDesc = strings.ReplaceAll(errDesc, "\"", "'")
				}
			}
		}
		wwwAuthHeader := generateWwwAuthenticateHeaderFromFields(ctx.Scheme, ctx.Authority, ctx.Vhost, ctx.APIContext, params, scopes, escapedDesc)
		headers[WWWAuthenticateHeader] = wwwAuthHeader
		headers[McpSessionHeader] = sessionId
		return policyv1alpha2.ImmediateResponse{
			StatusCode: ir.StatusCode,
			Headers:    headers,
			Body:       ir.Body,
		}
	}
	// Override AuthType to mcp/oauth: mcp-auth is the effective policy that ran
	if ctx.SharedContext.AuthContext != nil {
		ctx.SharedContext.AuthContext.AuthType = AuthType
	}
	if a, ok := headerAction.(policyv1alpha2.UpstreamRequestHeaderModifications); ok {
		return policyv1alpha2.UpstreamRequestModifications{
			UpstreamRequestHeaderModifications: a,
		}
	}
	return nil
}

// generateResourcePathFromFields builds the resource URL from individual context fields
// instead of a full RequestContext, enabling use in both header and body phases.
func generateResourcePathFromFields(scheme, authority, vhost, apiContext string, params map[string]any, resource string) string {
	_, port := parseAuthority(authority)

	var host string
	if vhost != "" && !strings.Contains(vhost, "*") {
		host = vhost
	} else {
		host = getStringParam(params, "gatewayHost", "localhost")
	}

	if port == -1 {
		if scheme == "https" {
			port = 8443
		} else {
			port = 8080
		}
	}

	hostWithPort := host
	if !isStandardPort(scheme, port) {
		hostWithPort = fmt.Sprintf("%s:%d", host, port)
	}

	if apiContext != "" {
		return fmt.Sprintf("%s://%s%s/%s", scheme, hostWithPort, apiContext, resource)
	}
	return fmt.Sprintf("%s://%s/%s", scheme, hostWithPort, resource)
}

// generateWwwAuthenticateHeaderFromFields builds the WWW-Authenticate header from individual context fields.
func generateWwwAuthenticateHeaderFromFields(scheme, authority, vhost, apiContext string, params map[string]any, scopes []string, errorDesc string) string {
	headerValue := AuthMethodBearer + "\"" + generateResourcePathFromFields(scheme, authority, vhost, apiContext, params, WellKnownPath) + "\""
	if len(scopes) > 0 {
		headerValue += ", scope=\"" + strings.Join(scopes, " ") + "\""
	}
	if errorDesc != "" {
		headerValue += ", error=\"invalid_token\", error_description=\"" + errorDesc + "\""
	}
	return headerValue
}
