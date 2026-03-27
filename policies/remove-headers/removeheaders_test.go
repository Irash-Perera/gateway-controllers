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

package removeheaders

import (
	"strings"
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Helper function to create test headers
func createTestHeaders(headers map[string]string) *policyv1alpha2.Headers {
	headerMap := make(map[string][]string)
	for k, v := range headers {
		headerMap[k] = []string{v}
	}
	return policyv1alpha2.NewHeaders(headerMap)
}

func TestRemoveHeadersPolicy_Mode(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	mode := p.Mode()

	expectedMode := policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha2.BodyModeSkip,
		ResponseHeaderMode: policyv1alpha2.HeaderModeProcess,
		ResponseBodyMode:   policyv1alpha2.BodyModeSkip,
	}

	if mode != expectedMode {
		t.Errorf("Expected mode %+v, got %+v", expectedMode, mode)
	}
}

func TestGetPolicy(t *testing.T) {
	metadata := policyv1alpha2.PolicyMetadata{}
	params := map[string]interface{}{}

	p, err := GetPolicyV2(metadata, params)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if p == nil {
		t.Fatal("Expected policy instance, got nil")
	}

	if _, ok := p.(*RemoveHeadersPolicy); !ok {
		t.Errorf("Expected RemoveHeadersPolicy, got %T", p)
	}
}

func TestRemoveHeadersPolicy_OnRequestHeaders_NoHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"content-type":  "application/json",
			"authorization": "Bearer token123",
		}),
	}

	// No requestHeaders parameter
	params := map[string]interface{}{}
	result := p.OnRequestHeaders(ctx, params)

	// Should return empty modifications
	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 0 {
		t.Errorf("Expected no headers to be removed, got %d headers", len(mods.HeadersToRemove))
	}
}

func TestRemoveHeadersPolicy_OnRequestHeaders_SingleHeader(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"content-type":    "application/json",
			"authorization":   "Bearer token123",
			"x-custom-header": "remove-me",
		}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "X-Custom-Header",
			},
		},
	}

	result := p.OnRequestHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 1 {
		t.Errorf("Expected 1 header to be removed, got %d headers", len(mods.HeadersToRemove))
	}

	expectedHeaderName := "x-custom-header" // Should be normalized to lowercase
	if mods.HeadersToRemove[0] != expectedHeaderName {
		t.Errorf("Expected header '%s' to be removed, got '%s'",
			expectedHeaderName, mods.HeadersToRemove[0])
	}
}

func TestRemoveHeadersPolicy_OnRequestHeaders_MultipleHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"content-type":  "application/json",
			"authorization": "Bearer token123",
			"x-api-key":     "secret",
			"x-client-id":   "client123",
			"x-debug-info":  "debug-data",
		}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "Authorization",
			},
			map[string]interface{}{
				"name": "X-API-Key",
			},
			map[string]interface{}{
				"name": "X-Debug-Info",
			},
		},
	}

	result := p.OnRequestHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 3 {
		t.Errorf("Expected 3 headers to be removed, got %d headers", len(mods.HeadersToRemove))
	}

	expectedHeaders := []string{"authorization", "x-api-key", "x-debug-info"}

	// Check that all expected headers are in the removal list
	for _, expectedHeader := range expectedHeaders {
		found := false
		for _, actualHeader := range mods.HeadersToRemove {
			if actualHeader == expectedHeader {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected header '%s' to be in removal list, got %v",
				expectedHeader, mods.HeadersToRemove)
		}
	}
}

func TestRemoveHeadersPolicy_OnRequestHeaders_HeaderNameNormalization(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"x-upper-case": "test-value",
		}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "  X-UPPER-CASE  ", // With spaces and uppercase
			},
		},
	}

	result := p.OnRequestHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	expectedHeaderName := "x-upper-case" // Should be trimmed and lowercase
	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != expectedHeaderName {
		t.Errorf("Expected header '%s' to be normalized and removed, got %v",
			expectedHeaderName, mods.HeadersToRemove)
	}
}

func TestRemoveHeadersPolicy_OnResponseHeaders_NoHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.ResponseHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"content-type": "application/json",
			"server":       "nginx/1.21.0",
		}),
	}

	// No responseHeaders parameter
	params := map[string]interface{}{}
	result := p.OnResponseHeaders(ctx, params)

	// Should return empty modifications
	mods, ok := result.(policyv1alpha2.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 0 {
		t.Errorf("Expected no headers to be removed, got %d headers", len(mods.HeadersToRemove))
	}
}

func TestRemoveHeadersPolicy_OnResponseHeaders_SingleHeader(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.ResponseHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"content-type": "application/json",
			"server":       "nginx/1.21.0",
			"x-powered-by": "Express",
		}),
	}

	params := map[string]interface{}{
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name": "X-Powered-By",
			},
		},
	}

	result := p.OnResponseHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 1 {
		t.Errorf("Expected 1 header to be removed, got %d headers", len(mods.HeadersToRemove))
	}

	expectedHeaderName := "x-powered-by" // Should be normalized to lowercase
	if mods.HeadersToRemove[0] != expectedHeaderName {
		t.Errorf("Expected header '%s' to be removed, got '%s'",
			expectedHeaderName, mods.HeadersToRemove[0])
	}
}

func TestRemoveHeadersPolicy_OnResponseHeaders_MultipleHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.ResponseHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"content-type":    "application/json",
			"server":          "nginx/1.21.0",
			"x-powered-by":    "Express",
			"x-frame-options": "SAMEORIGIN",
			"x-debug-trace":   "abc123",
		}),
	}

	params := map[string]interface{}{
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name": "Server",
			},
			map[string]interface{}{
				"name": "X-Powered-By",
			},
			map[string]interface{}{
				"name": "X-Debug-Trace",
			},
		},
	}

	result := p.OnResponseHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 3 {
		t.Errorf("Expected 3 headers to be removed, got %d headers", len(mods.HeadersToRemove))
	}

	expectedHeaders := []string{"server", "x-powered-by", "x-debug-trace"}

	// Check that all expected headers are in the removal list
	for _, expectedHeader := range expectedHeaders {
		found := false
		for _, actualHeader := range mods.HeadersToRemove {
			if actualHeader == expectedHeader {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected header '%s' to be in removal list, got %v",
				expectedHeader, mods.HeadersToRemove)
		}
	}
}

func TestRemoveHeadersPolicy_BothRequestAndResponse(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	// Test request phase
	reqCtx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"authorization": "Bearer token123",
		}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "Authorization",
			},
		},
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name": "Server",
			},
		},
	}

	reqResult := p.OnRequestHeaders(reqCtx, params)
	reqMods, ok := reqResult.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", reqResult)
	}

	if len(reqMods.HeadersToRemove) != 1 || reqMods.HeadersToRemove[0] != "authorization" {
		t.Errorf("Expected request header 'authorization' to be removed, got %v", reqMods.HeadersToRemove)
	}

	// Test response phase
	respCtx := &policyv1alpha2.ResponseHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"server": "nginx/1.21.0",
		}),
	}

	respResult := p.OnResponseHeaders(respCtx, params)
	respMods, ok := respResult.(policyv1alpha2.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", respResult)
	}

	if len(respMods.HeadersToRemove) != 1 || respMods.HeadersToRemove[0] != "server" {
		t.Errorf("Expected response header 'server' to be removed, got %v", respMods.HeadersToRemove)
	}
}

func TestRemoveHeadersPolicy_EmptyHeadersList(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{}, // Empty array
	}

	result := p.OnRequestHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 0 {
		t.Errorf("Expected no headers to be removed for empty array, got %d headers", len(mods.HeadersToRemove))
	}
}

func TestRemoveHeadersPolicy_InvalidHeadersType(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": "not-an-array", // Invalid type
	}

	result := p.OnRequestHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 0 {
		t.Errorf("Expected no headers to be removed for invalid type, got %d headers", len(mods.HeadersToRemove))
	}
}

func TestRemoveHeadersPolicy_InvalidHeaderEntry(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			123, // Invalid entry type (not object)
			map[string]interface{}{
				"name": "Valid-Header",
			}, // Valid entry
		},
	}

	result := p.OnRequestHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	// Should only process valid entries
	if len(mods.HeadersToRemove) != 1 {
		t.Errorf("Expected 1 valid header to be removed, got %d headers", len(mods.HeadersToRemove))
	}

	if mods.HeadersToRemove[0] != "valid-header" {
		t.Errorf("Expected valid header to be processed correctly, got '%s'", mods.HeadersToRemove[0])
	}
}

func TestRemoveHeadersPolicy_DuplicateHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "X-Custom-Header",
			},
			map[string]interface{}{
				"name": "X-Custom-Header", // Duplicate header name
			},
			map[string]interface{}{
				"name": "Authorization",
			},
		},
	}

	result := p.OnRequestHeaders(ctx, params)

	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 3 {
		t.Errorf("Expected 3 headers in removal list (including duplicates), got %d headers", len(mods.HeadersToRemove))
	}

	// Check that duplicates are preserved in the removal list
	expectedHeaders := []string{"x-custom-header", "x-custom-header", "authorization"}
	for i, expected := range expectedHeaders {
		if i < len(mods.HeadersToRemove) && mods.HeadersToRemove[i] != expected {
			t.Errorf("Expected header at index %d to be '%s', got '%s'", i, expected, mods.HeadersToRemove[i])
		}
	}
}

// Test validation methods
func TestRemoveHeadersPolicy_Validate_ValidConfiguration(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "Authorization",
			},
			map[string]interface{}{
				"name": "X-API-Key",
			},
		},
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name": "Server",
			},
			map[string]interface{}{
				"name": "X-Powered-By",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for valid configuration, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_OnlyRequestHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "Authorization",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for valid requestHeaders only, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_OnlyResponseHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name": "Server",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for valid responseHeaders only, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_NoHeadersSpecified(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "at least one of 'request.headers' or 'response.headers' must be specified") {
		t.Errorf("Expected 'at least one must be specified' error, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_InvalidRequestHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": "not-an-array", // Invalid type
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "must be an array") {
		t.Errorf("Expected 'must be an array' error, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_InvalidResponseHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"responseHeaders": []interface{}{
			123, // Invalid header entry (not object)
		},
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "must be an object with 'name' field") {
		t.Errorf("Expected 'must be an object with name field' error, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_EmptyRequestHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{}, // Empty array
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "request.headers cannot be empty") {
		t.Errorf("Expected 'request.headers cannot be empty' error, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_EmptyHeaderName(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "   ", // Empty/whitespace only name
			},
		},
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "name cannot be empty or whitespace-only") {
		t.Errorf("Expected 'name cannot be empty or whitespace-only' error, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_Validate_MissingNameField(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				// Missing name field
			},
		},
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "missing required 'name' field") {
		t.Errorf("Expected 'missing required name field' error, got: %v", err)
	}
}

func TestRemoveHeadersPolicy_OnRequestHeaders_NestedHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"x-nested-request": "remove-me",
		}),
	}

	params := map[string]interface{}{
		"request": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name": "X-Nested-Request",
				},
			},
		},
	}

	result := p.OnRequestHeaders(ctx, params)
	mods, ok := result.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != "x-nested-request" {
		t.Errorf("Expected nested request header to be removed, got %v", mods.HeadersToRemove)
	}
}

func TestRemoveHeadersPolicy_OnResponseHeaders_NestedHeaders(t *testing.T) {
	p := &RemoveHeadersPolicy{}
	ctx := &policyv1alpha2.ResponseHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"x-nested-response": "remove-me",
		}),
	}

	params := map[string]interface{}{
		"response": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name": "X-Nested-Response",
				},
			},
		},
	}

	result := p.OnResponseHeaders(ctx, params)
	mods, ok := result.(policyv1alpha2.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != "x-nested-response" {
		t.Errorf("Expected nested response header to be removed, got %v", mods.HeadersToRemove)
	}
}

func TestRemoveHeadersPolicy_Validate_NestedConfiguration(t *testing.T) {
	p := &RemoveHeadersPolicy{}

	params := map[string]interface{}{
		"request": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name": "Authorization",
				},
			},
		},
		"response": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name": "Server",
				},
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for nested configuration, got: %v", err)
	}
}
