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

package mcpauthz

import (
	"encoding/json"
	"strings"
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// createMockContext builds a RequestContext with a body and optional AuthContext,
// simulating that an upstream auth policy (mcp-auth/jwt-auth) already ran.
func createMockContext(method, path string, body []byte, authCtx *policyv1alpha2.AuthContext) *policyv1alpha2.RequestContext {
	return &policyv1alpha2.RequestContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID:   "test-request-id",
			Metadata:    make(map[string]any),
			AuthContext: authCtx,
		},
		Headers: policyv1alpha2.NewHeaders(nil),
		Body: &policyv1alpha2.Body{
			Content: body,
			Present: true,
		},
		Path:   path,
		Method: method,
		Scheme: "http",
	}
}

func authenticatedAuthCtx(scopes map[string]bool, subject, issuer string, audiences []string, props map[string]string) *policyv1alpha2.AuthContext {
	return &policyv1alpha2.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       subject,
		Issuer:        issuer,
		Audience:      audiences,
		Scopes:        scopes,
		Properties:    props,
	}
}

func toolsParam(tools []any) map[string]any {
	return map[string]any{"tools": tools}
}

func toolCallBody(toolName string) []byte {
	b, _ := json.Marshal(map[string]any{
		"method": "tools/call",
		"params": map[string]any{"name": toolName},
	})
	return b
}

// ---- GetPolicy ----

func TestGetPolicy(t *testing.T) {
	params := toolsParam([]any{
		map[string]any{
			"name":           "my-tool",
			"requiredScopes": []any{"mcp:tools:read"},
		},
	})
	p, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	if p == nil {
		t.Error("GetPolicy returned nil policy")
	}
}

func TestGetPolicy_EmptyParams(t *testing.T) {
	// Empty params should be valid (no rules configured means allow all)
	p, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, map[string]any{})
	if err != nil {
		t.Errorf("Expected no error for empty params, got: %v", err)
	}
	if p == nil {
		t.Error("Expected non-nil policy for empty params")
	}
}

// ---- Mode ----

func TestMode(t *testing.T) {
	p := &McpAuthzPolicy{}
	mode := p.Mode()
	if mode.RequestBodyMode != policyv1alpha2.BodyModeBuffer {
		t.Errorf("Expected RequestBodyMode=BodyModeBuffer, got %v", mode.RequestBodyMode)
	}
	if mode.RequestHeaderMode != policyv1alpha2.HeaderModeSkip {
		t.Errorf("Expected RequestHeaderMode=HeaderModeSkip, got %v", mode.RequestHeaderMode)
	}
}

// ---- OnRequest: path/method guard ----

func TestOnRequest_SkipsNonMCP_GET(t *testing.T) {
	p := &McpAuthzPolicy{}
	ctx := createMockContext("GET", "/mcp", toolCallBody("tool1"), authenticatedAuthCtx(nil, "alice", "", nil, nil))
	action := p.OnRequestBody(ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil for non-POST, got %T", action)
	}
}

func TestOnRequest_SkipsNonMCP_Path(t *testing.T) {
	p := &McpAuthzPolicy{}
	ctx := createMockContext("POST", "/api/resource", toolCallBody("tool1"), authenticatedAuthCtx(nil, "alice", "", nil, nil))
	action := p.OnRequestBody(ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil for non-/mcp path, got %T", action)
	}
}

// ---- OnRequest: AuthContext checks ----

func TestOnRequest_NoAuthContext(t *testing.T) {
	p := &McpAuthzPolicy{}
	ctx := createMockContext("POST", "/mcp", toolCallBody("tool1"), nil)
	action := p.OnRequestBody(ctx, map[string]any{})
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

func TestOnRequest_NotAuthenticated(t *testing.T) {
	p := &McpAuthzPolicy{}
	authCtx := &policyv1alpha2.AuthContext{Authenticated: false, AuthType: "jwt"}
	ctx := createMockContext("POST", "/mcp", toolCallBody("tool1"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

// ---- OnRequest: body parsing ----

func TestOnRequest_InvalidMCPBody(t *testing.T) {
	p := &McpAuthzPolicy{}
	authCtx := authenticatedAuthCtx(nil, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", []byte("not-json"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

// ---- OnRequest: rule matching ----

func TestOnRequest_NoMatchingRules(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "other-tool"},
			RequiredScopes: []string{"read"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"read": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (allow) when no rules match, got %T", action)
	}
}

func TestOnRequest_ScopeCheckPasses(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredScopes: []string{"mcp:tools:read"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"mcp:tools:read": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (authorized), got %T", action)
	}
}

func TestOnRequest_ScopeCheckFails(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredScopes: []string{"mcp:tools:write"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"mcp:tools:read": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse (forbidden), got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
	// WWW-Authenticate header should mention the missing scope
	wwwAuth := resp.Headers[WWWAuthenticateHeader]
	if !strings.Contains(wwwAuth, "mcp:tools:write") {
		t.Errorf("Expected missing scope in WWW-Authenticate header, got: %s", wwwAuth)
	}
}

func TestOnRequest_ClaimCheckPasses_Sub(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredClaims: map[string]string{"sub": "alice"},
		},
	}}
	authCtx := authenticatedAuthCtx(nil, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (authorized), got %T", action)
	}
}

func TestOnRequest_ClaimCheckFails(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredClaims: map[string]string{"sub": "bob"},
		},
	}}
	authCtx := authenticatedAuthCtx(nil, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse (forbidden), got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

func TestOnRequest_WildcardRule(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "*"},
			RequiredScopes: []string{"mcp:tools:call"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"mcp:tools:call": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("any-tool"), authCtx)
	action := p.OnRequestBody(ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (authorized by wildcard rule), got %T", action)
	}
}

// ---- AuthContext mutation on success ----

func TestOnRequest_Success_SetsAuthorizedAndAuthType(t *testing.T) {
	params := toolsParam([]any{
		map[string]any{
			"name":           "my-tool",
			"requiredScopes": []any{"mcp:tools:read"},
		},
	})
	p, _ := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, params)
	rp := p.(policyv1alpha2.RequestPolicy)

	authCtx := &policyv1alpha2.AuthContext{
		Authenticated: true,
		AuthType:      McpOAuthAuthType,
		Scopes:        map[string]bool{"mcp:tools:read": true},
	}
	body := toolCallBody("my-tool")
	ctx := createMockContext("POST", "/mcp", body, authCtx)

	action := rp.OnRequestBody(ctx, params)

	if action != nil {
		t.Fatalf("Expected nil (pass-through), got %T", action)
	}
	if !ctx.SharedContext.AuthContext.Authorized {
		t.Error("Expected AuthContext.Authorized=true after successful authz")
	}
	if ctx.SharedContext.AuthContext.AuthType != McpOAuthzAuthType {
		t.Errorf("Expected AuthType=%q, got %q", McpOAuthzAuthType, ctx.SharedContext.AuthContext.AuthType)
	}
}

func TestOnRequest_Success_NonMcpOAuthAuthType_Unchanged(t *testing.T) {
	params := toolsParam([]any{
		map[string]any{
			"name":           "my-tool",
			"requiredScopes": []any{"mcp:tools:read"},
		},
	})
	p, _ := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, params)
	rp := p.(policyv1alpha2.RequestPolicy)

	authCtx := &policyv1alpha2.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Scopes:        map[string]bool{"mcp:tools:read": true},
	}
	body := toolCallBody("my-tool")
	ctx := createMockContext("POST", "/mcp", body, authCtx)

	action := rp.OnRequestBody(ctx, params)

	if action != nil {
		t.Fatalf("Expected nil (pass-through), got %T", action)
	}
	if !ctx.SharedContext.AuthContext.Authorized {
		t.Error("Expected AuthContext.Authorized=true after successful authz")
	}
	// AuthType should be unchanged when it was not "mcp/oauth"
	if ctx.SharedContext.AuthContext.AuthType != "jwt" {
		t.Errorf("Expected AuthType='jwt' (unchanged), got %q", ctx.SharedContext.AuthContext.AuthType)
	}
}
