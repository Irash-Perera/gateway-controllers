/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package apikey

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	store "github.com/wso2/api-platform/common/apikey"
	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	AuthType = "apikey"

	applicationIDMetadataKey   = "x-wso2-application-id"
	applicationNameMetadataKey = "x-wso2-application-name"
)

// APIKeyPolicy implements API Key Authentication
type APIKeyPolicy struct {
}

var ins = &APIKeyPolicy{}

// GetPolicy is the v1alpha factory entry point (loaded by v1alpha kernels).
// The returned concrete type also satisfies policyv1alpha2 phase interfaces
// (StreamingResponsePolicy, RequestPolicy, ResponsePolicy), so v1alpha2 kernels
// can discover those capabilities via type assertions even when using this factory.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// GetPolicyV2 is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicyV2(
	metadata policyv1alpha2.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha2.Policy, error) {
	return ins, nil
}

// Mode returns the processing mode for this policy
func (p *APIKeyPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Process request headers for auth
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequest performs API Key Authentication
func (p *APIKeyPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	slog.Debug("API Key Auth Policy: OnRequest started",
		"path", ctx.Path,
		"method", ctx.Method,
		"apiId", ctx.APIId,
		"apiName", ctx.APIName,
		"apiVersion", ctx.APIVersion,
	)

	// Get configuration parameters
	keyName, ok := params["key"].(string)
	if !ok || keyName == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'key' configuration",
			"keyName", keyName,
			"ok", ok,
		)
		return p.handleAuthFailure(ctx, 401, "json", "Valid API key required",
			"missing or invalid 'key' configuration")
	}

	location, ok := params["in"].(string)
	if !ok || location == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'in' configuration",
			"location", location,
			"ok", ok,
		)
		return p.handleAuthFailure(ctx, 401, "json", "Valid API key required",
			"missing or invalid 'in' configuration")
	}

	issuer, _ := params["issuer"].(string)

	slog.Debug("API Key Auth Policy: Configuration loaded",
		"keyName", keyName,
		"location", location,
		"issuer", issuer,
	)

	// Extract API key based on location
	var providedKey string

	if location == "header" {
		// Check header (case-insensitive)
		if headerValues := ctx.Headers.Get(http.CanonicalHeaderKey(keyName)); len(headerValues) > 0 {
			providedKey = headerValues[0]
			slog.Debug("API Key Auth Policy: Found API key in header",
				"headerName", keyName,
				"keyLength", len(providedKey),
			)
		}
	} else if location == "query" {
		// Extract query parameters from the full path
		providedKey = extractQueryParam(ctx.Path, keyName)
		if providedKey != "" {
			slog.Debug("API Key Auth Policy: Found API key in query parameter",
				"paramName", keyName,
				"keyLength", len(providedKey),
			)
		}
	}

	// If no API key provided
	if providedKey == "" {
		slog.Debug("API Key Auth Policy: No API key found",
			"location", location,
			"keyName", keyName,
		)
		return p.handleAuthFailure(ctx, 401, "json", "Valid API key required",
			"missing API key")
	}

	apiId := ctx.APIId
	apiName := ctx.APIName
	apiVersion := ctx.APIVersion
	apiOperation := ctx.OperationPath
	operationMethod := ctx.Method

	if apiId == "" || apiName == "" || apiVersion == "" || apiOperation == "" || operationMethod == "" {
		slog.Debug("API Key Auth Policy: Missing API details for validation",
			"apiId", apiId,
			"apiName", apiName,
			"apiVersion", apiVersion,
			"apiOperation", apiOperation,
			"operationMethod", operationMethod,
		)
		return p.handleAuthFailure(ctx, 401, "json", "Valid API key required",
			"missing API details for validation")
	}

	slog.Debug("API Key Auth Policy: Starting validation",
		"apiId", apiId,
		"apiName", apiName,
		"apiVersion", apiVersion,
		"apiOperation", apiOperation,
		"operationMethod", operationMethod,
		"keyLength", len(providedKey),
	)

	// API key was provided - validate it using external validation
	resolvedKey, err := p.resolveValidatedAPIKey(apiId, apiOperation, operationMethod, providedKey, issuer)
	if err != nil {
		slog.Debug("API Key Auth Policy: Validation error",
			"error", err,
		)
		return p.handleAuthFailure(ctx, 401, "json", "Valid API key required",
			"error validating API key")
	}
	if resolvedKey == nil {
		slog.Debug("API Key Auth Policy: Invalid API key")
		return p.handleAuthFailure(ctx, 401, "json", "Valid API key required",
			"invalid API key")
	}

	// Authentication successful
	slog.Debug("API Key Auth Policy: Authentication successful")
	return p.handleAuthSuccess(ctx, resolvedKey)
}

// handleAuthSuccess handles successful authentication
func (p *APIKeyPolicy) handleAuthSuccess(ctx *policy.RequestContext, resolvedKey *store.APIKey) policy.RequestAction {
	slog.Debug("API Key Auth Policy: handleAuthSuccess called",
		"apiId", ctx.APIId,
		"apiName", ctx.APIName,
		"apiVersion", ctx.APIVersion,
		"method", ctx.Method,
		"path", ctx.Path,
	)

	ctx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		CredentialID:  resolvedKey.ID,
		Previous:      ctx.SharedContext.AuthContext,
		Properties: map[string]string{
			"ApplicationName": resolvedKey.ApplicationName,
			"ApplicationID":   resolvedKey.ApplicationID,
		},
	}

	analyticsMetadata := map[string]any{}
	if strings.TrimSpace(resolvedKey.ApplicationID) != "" {
		analyticsMetadata[applicationIDMetadataKey] = strings.TrimSpace(resolvedKey.ApplicationID)
	}
	if strings.TrimSpace(resolvedKey.ApplicationName) != "" {
		analyticsMetadata[applicationNameMetadataKey] = strings.TrimSpace(resolvedKey.ApplicationName)
	}

	if len(analyticsMetadata) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	return policy.UpstreamRequestModifications{
		AnalyticsMetadata: analyticsMetadata,
	}
}

// OnResponse is not used by this policy (authentication is request-only)
func (p *APIKeyPolicy) OnResponse(_ctx *policy.ResponseContext, _params map[string]interface{}) policy.ResponseAction {
	return nil // No response processing needed
}

// handleAuthFailure handles authentication failure
func (p *APIKeyPolicy) handleAuthFailure(ctx *policy.RequestContext, statusCode int, errorFormat, errorMessage,
	reason string) policy.RequestAction {
	slog.Debug("API Key Auth Policy: handleAuthFailure called",
		"statusCode", statusCode,
		"errorFormat", errorFormat,
		"errorMessage", errorMessage,
		"reason", reason,
		"apiId", ctx.APIId,
		"apiName", ctx.APIName,
		"apiVersion", ctx.APIVersion,
		"method", ctx.Method,
		"path", ctx.Path,
	)

	ctx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      ctx.SharedContext.AuthContext,
	}

	headers := map[string]string{
		"content-type": "application/json",
	}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	default: // json
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}

	slog.Debug("API Key Auth Policy: Returning immediate response",
		"statusCode", statusCode,
		"contentType", headers["content-type"],
		"bodyLength", len(body),
		"reason", reason,
	)

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

// resolveValidatedAPIKey validates the provided API key against external store/service and returns the resolved key
// returns nil if the key is invalid, or an error if there was an issue during validation
func (p *APIKeyPolicy) resolveValidatedAPIKey(apiId, apiOperation, operationMethod, apiKey, issuer string) (*store.APIKey, error) {
	apiKeyStore := store.GetAPIkeyStoreInstance()
	resolvedKey, err := apiKeyStore.ResolveValidatedAPIKey(apiId, apiOperation, operationMethod, apiKey, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve API key via the policy engine")
	}
	return resolvedKey, nil
}

// extractQueryParam extracts the first value of the given query parameter from the request path
func extractQueryParam(path, param string) string {
	// Parse the URL-encoded path
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return ""
	}

	// Split the path into components
	parts := strings.Split(decodedPath, "?")
	if len(parts) != 2 {
		return ""
	}

	// Parse the query string
	queryString := parts[1]
	values, err := url.ParseQuery(queryString)
	if err != nil {
		return ""
	}

	// Get the first value of the specified parameter
	if value, ok := values[param]; ok && len(value) > 0 {
		return value[0]
	}

	return ""
}

// ─── v2alpha.RequestHeaderPolicy ─────────────────────────────────────────────

// OnRequestHeaders implements v1alpha2.RequestHeaderPolicy.
// It performs API key authentication in the request-header phase, allowing the
// kernel to short-circuit before any body buffering occurs.
func (p *APIKeyPolicy) OnRequestHeaders(ctx *policyv1alpha2.RequestHeaderContext, params map[string]interface{}) policyv1alpha2.RequestHeaderAction {
	if errResp := p.authenticate(ctx.SharedContext, ctx.Headers, ctx.Path, ctx.Method, params); errResp != nil {
		return *errResp
	}
	return policyv1alpha2.UpstreamRequestHeaderModifications{}
}

// authenticate is the shared core logic for OnRequestHeaders.
// It extracts and validates the API key, sets SharedContext.AuthContext, and returns
// nil on success or an *ImmediateResponse on failure.
func (p *APIKeyPolicy) authenticate(
	shared *policyv1alpha2.SharedContext,
	headers *policyv1alpha2.Headers,
	path, method string,
	params map[string]interface{},
) *policyv1alpha2.ImmediateResponse {
	slog.Debug("API Key Auth Policy: authenticate started",
		"path", path,
		"method", method,
		"apiId", shared.APIId,
		"apiName", shared.APIName,
		"apiVersion", shared.APIVersion,
	)

	keyName, ok := params["key"].(string)
	if !ok || keyName == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'key' configuration")
		return p.failAuthV2(shared, 401, "json", "Valid API key required",
			"missing or invalid 'key' configuration")
	}

	location, ok := params["in"].(string)
	if !ok || location == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'in' configuration")
		return p.failAuthV2(shared, 401, "json", "Valid API key required",
			"missing or invalid 'in' configuration")
	}

	issuer, _ := params["issuer"].(string)

	slog.Debug("API Key Auth Policy: Configuration loaded", "keyName", keyName, "location", location)

	var providedKey string
	switch location {
	case "header":
		if vals := headers.Get(http.CanonicalHeaderKey(keyName)); len(vals) > 0 {
			providedKey = vals[0]
			slog.Debug("API Key Auth Policy: Found API key in header",
				"headerName", keyName, "keyLength", len(providedKey))
		}
	case "query":
		providedKey = extractQueryParam(path, keyName)
		if providedKey != "" {
			slog.Debug("API Key Auth Policy: Found API key in query parameter",
				"paramName", keyName, "keyLength", len(providedKey))
		}
	default:
		slog.Debug("API Key Auth Policy: Unsupported location", "location", location)
		return p.failAuthV2(shared, 401, "json", "Valid API key required",
			"missing or invalid 'in' configuration")
	}

	if providedKey == "" {
		slog.Debug("API Key Auth Policy: No API key found", "location", location, "keyName", keyName)
		return p.failAuthV2(shared, 401, "json", "Valid API key required", "missing API key")
	}

	apiId := shared.APIId
	apiName := shared.APIName
	apiVersion := shared.APIVersion
	apiOperation := shared.OperationPath
	operationMethod := method

	if apiId == "" || apiName == "" || apiVersion == "" || apiOperation == "" || operationMethod == "" {
		slog.Debug("API Key Auth Policy: Missing API details for validation",
			"apiId", apiId, "apiName", apiName, "apiVersion", apiVersion,
			"apiOperation", apiOperation, "operationMethod", operationMethod)
		return p.failAuthV2(shared, 401, "json", "Valid API key required",
			"missing API details for validation")
	}

	slog.Debug("API Key Auth Policy: Starting validation",
		"apiId", apiId, "apiName", apiName, "apiVersion", apiVersion,
		"apiOperation", apiOperation, "operationMethod", operationMethod,
		"keyLength", len(providedKey))

	resolvedKey, err := p.resolveValidatedAPIKey(apiId, apiOperation, operationMethod, providedKey, issuer)
	if err != nil {
		slog.Debug("API Key Auth Policy: Validation error", "error", err)
		return p.failAuthV2(shared, 401, "json", "Valid API key required",
			"error validating API key")
	}
	if resolvedKey == nil {
		slog.Debug("API Key Auth Policy: Invalid API key")
		return p.failAuthV2(shared, 401, "json", "Valid API key required", "invalid API key")
	}

	slog.Debug("API Key Auth Policy: Authentication successful")
	shared.AuthContext = &policyv1alpha2.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}
	return nil
}

// failAuthV2 sets the auth context to unauthenticated and returns a policyv1alpha2.ImmediateResponse.
func (p *APIKeyPolicy) failAuthV2(shared *policyv1alpha2.SharedContext, statusCode int, errorFormat, errorMessage, reason string) *policyv1alpha2.ImmediateResponse {
	shared.AuthContext = &policyv1alpha2.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}
	v1resp := p.buildErrorResponse(statusCode, errorFormat, errorMessage, reason)
	return &policyv1alpha2.ImmediateResponse{
		StatusCode: v1resp.StatusCode,
		Headers:    v1resp.Headers,
		Body:       v1resp.Body,
	}
}

// buildErrorResponse constructs the ImmediateResponse body and headers for an auth failure.
func (p *APIKeyPolicy) buildErrorResponse(statusCode int, errorFormat, errorMessage, reason string) policyv1alpha2.ImmediateResponse {
	headers := map[string]string{"content-type": "application/json"}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	default: // json
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}

	slog.Debug("API Key Auth Policy: Returning immediate response",
		"statusCode", statusCode,
		"contentType", headers["content-type"],
		"bodyLength", len(body),
		"reason", reason,
	)

	return policyv1alpha2.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}
