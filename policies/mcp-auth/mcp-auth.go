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
	policyv1alpha "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
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

type McpAuthPolicy struct{}

type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

var ins = &McpAuthPolicy{}

func GetPolicy(
	metadata policyv1alpha.PolicyMetadata,
	params map[string]any,
) (policyv1alpha.Policy, error) {
	slog.Debug("MCP Auth Policy: GetPolicy called")
	return ins, nil
}

func (p *McpAuthPolicy) Mode() policyv1alpha.ProcessingMode {
	return policyv1alpha.ProcessingMode{
		RequestHeaderMode:  policyv1alpha.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha.BodyModeSkip,
		ResponseHeaderMode: policyv1alpha.HeaderModeSkip,
		ResponseBodyMode:   policyv1alpha.BodyModeSkip,
	}
}

func (p *McpAuthPolicy) OnRequest(ctx *policyv1alpha.RequestContext, params map[string]any) policyv1alpha.RequestAction {
	userIssuers := getStringArrayParam(params, "issuers", []string{})
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", 401)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", "json")
	userRequiredScopes := getStringArrayParam(params, "requiredScopes", []string{})
	if err := validateAuthFailureConfig(onFailureStatusCode, errorMessageFormat); err != nil {
		return buildInvalidConfigResponse(err.Error())
	}

	gatewayHost := getStringParam(params, "gatewayHost", "")
	if gatewayHost != "" {
		ensureRequestMetadata(ctx)
		ctx.Metadata["gatewayHost"] = gatewayHost
	}
	// Check for GET /.well-known/oauth-protected-resource
	if ctx.Method == "GET" && isWellKnownEndpointRequest(ctx.Path) {
		slog.Debug("MCP Auth Policy: Handling well-known protected resource metadata request")
		sessionIds := ctx.Headers.Get(McpSessionHeader)
		sessionId := ""
		if len(sessionIds) > 0 {
			sessionId = sessionIds[0]
		}

		// Get key managers configuration
		keyManagersRaw, ok := params["keyManagers"]
		if !ok {
			slog.Debug("MCP Auth Policy: Key managers not configured in params")
			return p.handleAuthFailure(ctx, onFailureStatusCode, errorMessageFormat, "key managers not configured")
		}

		slog.Debug("MCP Auth Policy: Starting to parse key managers configuration")

		issuers, kms, err := parseKeyManagers(keyManagersRaw)
		if err != nil {
			return buildInvalidConfigResponse(err.Error())
		}
		if len(issuers) == 0 {
			return p.handleAuthFailure(ctx, onFailureStatusCode, errorMessageFormat, "no valid key managers found")
		}

		if len(userIssuers) > 0 {
			filteredIssuers := []string{}
			for _, ui := range userIssuers {
				if issuer, ok := kms[ui]; ok {
					filteredIssuers = append(filteredIssuers, issuer)
					slog.Debug("MCP Auth Policy: Added issuer from user configuration", "issuer", issuer)
				}
			}
			issuers = filteredIssuers
		}

		if len(issuers) == 0 {
			return p.handleAuthFailure(ctx, onFailureStatusCode, errorMessageFormat, "no matching issuers found")
		}

		// todo: mcp auth flow
		prm := ProtectedResourceMetadata{
			Resource:             generateResourcePath(ctx, params, "mcp"),
			AuthorizationServers: issuers,
			ScopesSupported:      userRequiredScopes,
		}
		jsonOut, _ := json.Marshal(prm)
		return policyv1alpha.ImmediateResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type":   "application/json",
				McpSessionHeader: sessionId,
			},
			Body: jsonOut,
		}
	}
	return p.handleAuth(ctx, params, userRequiredScopes)
}

func (p *McpAuthPolicy) OnResponse(ctx *policyv1alpha.ResponseContext, params map[string]any) policyv1alpha.ResponseAction {
	return nil
}

// OnRequestHeaders processes the request header phase for MCP authentication.
func (p *McpAuthPolicy) OnRequestHeaders(ctx *policyv1alpha2.RequestHeaderContext, params map[string]any) policyv1alpha2.RequestHeaderAction {
	userIssuers := getStringArrayParam(params, "issuers", []string{})
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", 401)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", "json")
	userRequiredScopes := getStringArrayParam(params, "requiredScopes", []string{})
	if err := validateAuthFailureConfig(onFailureStatusCode, errorMessageFormat); err != nil {
		v1r := buildInvalidConfigResponse(err.Error()).(policyv1alpha.ImmediateResponse)
		return policyv1alpha2.ImmediateResponse{StatusCode: v1r.StatusCode, Headers: v1r.Headers, Body: v1r.Body}
	}

	gatewayHost := getStringParam(params, "gatewayHost", "")
	if gatewayHost != "" {
		if ctx.Metadata == nil {
			ctx.SharedContext.Metadata = map[string]any{}
		}
		ctx.Metadata["gatewayHost"] = gatewayHost
	}

	// Check for GET /.well-known/oauth-protected-resource
	if ctx.Method == "GET" && isWellKnownEndpointRequest(ctx.Path) {
		sessionIds := ctx.Headers.Get(McpSessionHeader)
		sessionId := ""
		if len(sessionIds) > 0 {
			sessionId = sessionIds[0]
		}

		keyManagersRaw, ok := params["keyManagers"]
		if !ok {
			return p.handleAuthFailureHeaders(ctx.SharedContext, onFailureStatusCode, errorMessageFormat, "key managers not configured")
		}

		issuers, kms, err := parseKeyManagers(keyManagersRaw)
		if err != nil {
			v1r := buildInvalidConfigResponse(err.Error()).(policyv1alpha.ImmediateResponse)
			return policyv1alpha2.ImmediateResponse{StatusCode: v1r.StatusCode, Headers: v1r.Headers, Body: v1r.Body}
		}
		if len(issuers) == 0 {
			return p.handleAuthFailureHeaders(ctx.SharedContext, onFailureStatusCode, errorMessageFormat, "no valid key managers found")
		}

		if len(userIssuers) > 0 {
			filteredIssuers := []string{}
			for _, ui := range userIssuers {
				if issuer, ok := kms[ui]; ok {
					filteredIssuers = append(filteredIssuers, issuer)
				}
			}
			issuers = filteredIssuers
		}

		if len(issuers) == 0 {
			return p.handleAuthFailureHeaders(ctx.SharedContext, onFailureStatusCode, errorMessageFormat, "no matching issuers found")
		}

		prm := ProtectedResourceMetadata{
			Resource:             generateResourcePathFromFields(ctx.Scheme, ctx.Authority, ctx.Vhost, ctx.APIContext, params, "mcp"),
			AuthorizationServers: issuers,
			ScopesSupported:      userRequiredScopes,
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
	return p.handleAuthHeaders(ctx, params, userRequiredScopes)
}

// handleAuthHeaders performs MCP authentication in the request header phase.
func (p *McpAuthPolicy) handleAuthHeaders(ctx *policyv1alpha2.RequestHeaderContext, params map[string]any, scopes []string) policyv1alpha2.RequestHeaderAction {
	type requestHeaderPolicer interface {
		OnRequestHeaders(*policyv1alpha2.RequestHeaderContext, map[string]interface{}) policyv1alpha2.RequestHeaderAction
	}

	sessionIds := ctx.Headers.Get(McpSessionHeader)
	sessionId := ""
	if len(sessionIds) > 0 {
		sessionId = sessionIds[0]
	}

	jwtPolicy, _ := jwtauth.GetPolicy(policyv1alpha.PolicyMetadata{}, params)
	hrp, ok := jwtPolicy.(requestHeaderPolicer)
	if !ok {
		return policyv1alpha2.UpstreamRequestHeaderModifications{}
	}

	headerAction := hrp.OnRequestHeaders(ctx, params)
	if ir, ok := headerAction.(policyv1alpha2.ImmediateResponse); ok {
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
	if ctx.SharedContext.AuthContext != nil {
		ctx.SharedContext.AuthContext.AuthType = AuthType
	}
	return headerAction
}

// handleAuthFailureHeaders constructs an authentication failure response in the header phase.
func (p *McpAuthPolicy) handleAuthFailureHeaders(shared *policyv1alpha2.SharedContext, statusCode int, format string, reason any) policyv1alpha2.RequestHeaderAction {
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

// handleAuth does the MCP specific authentication handling
func (p *McpAuthPolicy) handleAuth(ctx *policyv1alpha.RequestContext, params map[string]any, scopes []string) policyv1alpha.RequestAction {
	sessionIds := ctx.Headers.Get(McpSessionHeader)
	sessionId := ""
	if len(sessionIds) > 0 {
		sessionId = sessionIds[0]
	}

	slog.Debug("MCP Auth Policy: Delegating authentication to JWT Auth Policy")
	jwtPolicy, _ := jwtauth.GetPolicy(policyv1alpha.PolicyMetadata{}, params)
	reqAction := jwtPolicy.OnRequest(ctx, params)
	if _, ok := reqAction.(policyv1alpha.ImmediateResponse); ok {
		slog.Debug("MCP Auth Policy: Authentication failed in JWT Auth Policy, handling failure")
		// Take ownership of AuthContext: mcp-auth is the effective policy that ran
		ctx.SharedContext.AuthContext = &policyv1alpha.AuthContext{
			Authenticated: false,
			AuthType:      AuthType,
			Previous:      ctx.SharedContext.AuthContext,
		}
		headers := reqAction.(policyv1alpha.ImmediateResponse).Headers
		ir := reqAction.(policyv1alpha.ImmediateResponse)
		escapedDesc := ""
		contentType := ir.Headers["content-type"]
		if contentType == "application/json" {
			var errResp map[string]any
			if err := json.Unmarshal(ir.Body, &errResp); err == nil {
				if errDesc, ok := errResp["message"].(string); ok {
					escapedDesc = strings.ReplaceAll(errDesc, "\"", "'")
				}
			}
		}
		wwwAuthHeader := generateWwwAuthenticateHeader(ctx, params, scopes, escapedDesc)
		headers[WWWAuthenticateHeader] = wwwAuthHeader
		headers[McpSessionHeader] = sessionId
		return policyv1alpha.ImmediateResponse{
			StatusCode: reqAction.(policyv1alpha.ImmediateResponse).StatusCode,
			Headers:    headers,
			Body:       reqAction.(policyv1alpha.ImmediateResponse).Body,
		}
	}
	// Override AuthType to mcp/oauth: mcp-auth is the effective policy that ran
	if ctx.SharedContext.AuthContext != nil {
		ctx.SharedContext.AuthContext.AuthType = AuthType
	}
	return reqAction
}

func (p *McpAuthPolicy) handleAuthFailure(ctx *policyv1alpha.RequestContext, statusCode int, format string, reason any) policyv1alpha.RequestAction {
	slog.Debug("MCP Auth Policy: Handling authentication failure", "statusCode", statusCode, "reason", reason)
	ctx.SharedContext.AuthContext = &policyv1alpha.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      ctx.SharedContext.AuthContext,
	}
	ensureRequestMetadata(ctx)
	ctx.Metadata[MetadataKeyAuthSuccess] = false
	ctx.Metadata[MetadataKeyAuthMethod] = "mcpAuth"
	var body string
	headers := map[string]string{
		"content-type": "application/json",
	}
	switch format {
	case "plain":
		body = fmt.Sprintf("Authentication failed: %s", reason)
		headers["content-type"] = "text/plain"
	case "minimal":
		body = "Unauthorized"
	default: // json
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": fmt.Sprintf("MCP authentication failed: %s", reason),
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}

	return policyv1alpha.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

// generateResourcePath generates the full resource URL for the given resource path
func generateResourcePath(ctx *policyv1alpha.RequestContext, params map[string]any, resource string) string {
	slog.Debug("MCP Auth Policy: Generating resource path for", "resource", resource)

	scheme := ctx.Scheme
	_, port := parseAuthority(ctx.Authority)

	// Determine the host - prefer vhost, fallback to gatewayHost param
	var host string
	if ctx.Vhost != "" && !strings.Contains(ctx.Vhost, "*") {
		host = ctx.Vhost
		slog.Debug("MCP Auth Policy: Using VHost with port from context", "vhost", host)
	} else {
		host = getStringParam(params, "gatewayHost", "localhost")
		slog.Debug("MCP Auth Policy: VHost not found, using gateway host from params", "host", host)
	}

	// Determine port if not present in authority
	if port == -1 {
		slog.Debug("MCP Auth Policy: No port specified, using default port based on scheme")
		if scheme == "https" {
			port = 8443
		} else {
			port = 8080
		}
	}

	// Build host:port, omitting standard ports
	hostWithPort := host
	if !isStandardPort(scheme, port) {
		slog.Debug("MCP Auth Policy: Adding non-standard port to host", "port", port)
		hostWithPort = fmt.Sprintf("%s:%d", host, port)
	}

	// Build the full URL path
	apiContext := ctx.APIContext
	if apiContext != "" {
		return fmt.Sprintf("%s://%s%s/%s", scheme, hostWithPort, apiContext, resource)
	}
	return fmt.Sprintf("%s://%s/%s", scheme, hostWithPort, resource)
}

// generateWwwAuthenticateHeader generates the WWW-Authenticate header value
func generateWwwAuthenticateHeader(ctx *policyv1alpha.RequestContext, params map[string]any, scopes []string, errorDesc string) string {
	slog.Debug("MCP Auth Policy: Generating WWW-Authenticate header")
	headerValue := AuthMethodBearer + "\"" + generateResourcePath(ctx, params, WellKnownPath) + "\""
	if len(scopes) > 0 {
		slog.Debug("MCP Auth Policy: Adding scopes to WWW-Authenticate header")
		headerValue += ", scope=\"" + strings.Join(scopes, " ") + "\""
	}
	if errorDesc != "" {
		slog.Debug("MCP Auth Policy: Adding error description to WWW-Authenticate header")
		headerValue += ", error=\"invalid_token\", error_description=\"" + errorDesc + "\""
	}
	return headerValue
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

func buildInvalidConfigResponse(message string) policyv1alpha.RequestAction {
	body, _ := json.Marshal(map[string]string{
		"error":   "Internal Server Error",
		"message": message,
	})
	return policyv1alpha.ImmediateResponse{
		StatusCode: 500,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body: body,
	}
}

func ensureRequestMetadata(ctx *policyv1alpha.RequestContext) {
	if ctx.SharedContext == nil {
		ctx.SharedContext = &policyv1alpha.SharedContext{}
	}
	if ctx.Metadata == nil {
		ctx.Metadata = map[string]any{}
	}
}
