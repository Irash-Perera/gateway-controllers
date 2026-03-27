package apikey

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	apikeycommon "github.com/wso2/api-platform/common/apikey"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestAPIKeyPolicy_Mode(t *testing.T) {
	p := &APIKeyPolicy{}
	got := p.Mode()
	want := policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha2.BodyModeSkip,
		ResponseHeaderMode: policyv1alpha2.HeaderModeSkip,
		ResponseBodyMode:   policyv1alpha2.BodyModeSkip,
	}

	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestGetPolicy_ReturnsSingleton(t *testing.T) {
	p1, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicyV2 failed: %v", err)
	}
	p2, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicyV2 failed: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_SuccessFromHeader(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "header-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		http.CanonicalHeaderKey("x-api-key"): {"header-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected AuthContext.Authenticated=true")
	}
	if ctx.SharedContext.AuthContext.AuthType != "apikey" {
		t.Fatalf("expected AuthType='apikey', got %q", ctx.SharedContext.AuthContext.AuthType)
	}
	if _, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_SuccessFromQuery(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-2", "query-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders?x_api_key=query-secret", nil, "api-2", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(ctx, map[string]interface{}{
		"key": "x_api_key",
		"in":  "query",
	})

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected AuthContext.Authenticated=true")
	}
	if _, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_MissingOrInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
	}{
		{
			name: "missing key",
			params: map[string]interface{}{
				"in": "header",
			},
		},
		{
			name: "missing in",
			params: map[string]interface{}{
				"key": "x-api-key",
			},
		},
		{
			name: "unsupported in",
			params: map[string]interface{}{
				"key": "x-api-key",
				"in":  "cookie",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetAPIKeyStore(t)
			p := &APIKeyPolicy{}
			ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
				"x-api-key": {"header-secret"},
			}, "api-1", "OrdersAPI", "v1", "/orders")

			action := p.OnRequestHeaders(ctx, tt.params)
			assertUnauthorizedJSON(t, action)

			if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
				t.Fatalf("expected AuthContext.Authenticated=false")
			}
		})
	}
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenAPIKeyMissing(t *testing.T) {
	resetAPIKeyStore(t)
	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders?foo=bar", nil, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(ctx, map[string]interface{}{
		"key": "x_api_key",
		"in":  "query",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenAPIDetailsMissing(t *testing.T) {
	resetAPIKeyStore(t)
	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"header-secret"},
	}, "api-1", "", "v1", "/orders")

	action := p.OnRequestHeaders(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenValidationReturnsFalse(t *testing.T) {
	resetAPIKeyStore(t)
	seedExternalAPIKey(t, "api-1", "different-secret", `["GET /orders"]`)

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"wrong-secret"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_OnRequestHeaders_FailsWhenValidationErrors(t *testing.T) {
	resetAPIKeyStore(t)
	// Do not seed any key for "api-1" so ValidateAPIKey returns ErrNotFound.

	p := &APIKeyPolicy{}
	ctx := newRequestHeaderContext(t, "GET", "/orders", map[string][]string{
		"x-api-key": {"no-matching-key"},
	}, "api-1", "OrdersAPI", "v1", "/orders")

	action := p.OnRequestHeaders(ctx, map[string]interface{}{
		"key": "x-api-key",
		"in":  "header",
	})

	assertUnauthorizedJSON(t, action)
}

func TestAPIKeyPolicy_HandleAuthFailure_PlainFormat(t *testing.T) {
	p := &APIKeyPolicy{}
	// handleAuthFailure uses v1alpha RequestContext
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
			APIId:     "api-1",
			APIName:   "OrdersAPI",
		},
		Headers: policy.NewHeaders(nil),
		Method:  "GET",
		Path:    "/orders",
	}

	action := p.handleAuthFailure(ctx, 401, "plain", "Auth failed", "test failure")
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.Headers["content-type"] != "text/plain" {
		t.Fatalf("unexpected content-type: %q", resp.Headers["content-type"])
	}
	if string(resp.Body) != "Auth failed" {
		t.Fatalf("unexpected body: %q", string(resp.Body))
	}
}

func TestExtractQueryParam(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		param    string
		expected string
	}{
		{
			name:     "simple query",
			path:     "/orders?token=abc123",
			param:    "token",
			expected: "abc123",
		},
		{
			name:     "encoded path",
			path:     "/orders%3Ftoken%3Dabc123",
			param:    "token",
			expected: "abc123",
		},
		{
			name:     "multiple values takes first",
			path:     "/orders?token=first&token=second",
			param:    "token",
			expected: "first",
		},
		{
			name:     "missing query",
			path:     "/orders",
			param:    "token",
			expected: "",
		},
		{
			name:     "invalid escaped path",
			path:     "%",
			param:    "token",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractQueryParam(tt.path, tt.param)
			if got != tt.expected {
				t.Fatalf("unexpected value: got %q, want %q", got, tt.expected)
			}
		})
	}
}

func newRequestHeaderContext(t *testing.T, method, path string, headers map[string][]string, apiID, apiName, apiVersion, opPath string) *policyv1alpha2.RequestHeaderContext {
	t.Helper()
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID:     "req-1",
			Metadata:      map[string]interface{}{},
			APIId:         apiID,
			APIName:       apiName,
			APIVersion:    apiVersion,
			OperationPath: opPath,
		},
		Headers: policyv1alpha2.NewHeaders(headers),
		Method:  method,
		Path:    path,
	}
}

func assertUnauthorizedJSON(t *testing.T, action policyv1alpha2.RequestHeaderAction) {
	t.Helper()
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", resp.Headers["content-type"])
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] != "Unauthorized" {
		t.Fatalf("unexpected error value: %v", body["error"])
	}
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "Valid API key required") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func resetAPIKeyStore(t *testing.T) {
	t.Helper()
	if err := apikeycommon.GetAPIkeyStoreInstance().ClearAll(); err != nil {
		t.Fatalf("failed to clear API key store: %v", err)
	}
}

func seedExternalAPIKey(t *testing.T, apiID, plainKey, operations string) {
	t.Helper()
	key := &apikeycommon.APIKey{
		ID:          "id-" + sanitizeTestName(t.Name()),
		Name:        "name-" + sanitizeTestName(t.Name()),
		DisplayName: "test-key",
		APIKey:      apikeycommon.ComputeAPIKeyHash(plainKey),
		APIId:       apiID,
		Operations:  operations,
		Status:      apikeycommon.Active,
		Source:      "external",
	}
	if err := apikeycommon.GetAPIkeyStoreInstance().StoreAPIKey(apiID, key); err != nil {
		t.Fatalf("failed to store API key: %v", err)
	}
}

func sanitizeTestName(v string) string {
	v = strings.ReplaceAll(v, "/", "-")
	v = strings.ReplaceAll(v, " ", "-")
	return strings.ToLower(v)
}

func TestAPIKeyPolicy_AuthContext_PreviousPreserved_OnSuccess(t *testing.T) {
	p := &APIKeyPolicy{}
	prior := &policy.AuthContext{Authenticated: true, AuthType: "other"}
	// handleAuthSuccess uses v1alpha RequestContext
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "req-1",
			Metadata:      map[string]interface{}{},
			APIId:         "api-1",
			APIName:       "OrdersAPI",
			APIVersion:    "v1",
			OperationPath: "/orders",
		},
		Headers: policy.NewHeaders(nil),
		Method:  "GET",
		Path:    "/orders",
	}
	ctx.SharedContext.AuthContext = prior

	p.handleAuthSuccess(ctx, &apikeycommon.APIKey{})

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Previous != prior {
		t.Errorf("Expected Previous to point to prior AuthContext, got %v", ctx.SharedContext.AuthContext.Previous)
	}
}

func TestAPIKeyPolicy_AuthContext_PreviousPreserved_OnFailure(t *testing.T) {
	p := &APIKeyPolicy{}
	prior := &policy.AuthContext{Authenticated: true, AuthType: "other"}
	// handleAuthFailure uses v1alpha RequestContext
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "req-1",
			Metadata:      map[string]interface{}{},
			APIId:         "api-1",
			APIName:       "OrdersAPI",
			APIVersion:    "v1",
			OperationPath: "/orders",
		},
		Headers: policy.NewHeaders(nil),
		Method:  "GET",
		Path:    "/orders",
	}
	ctx.SharedContext.AuthContext = prior

	p.handleAuthFailure(ctx, 401, "json", "Valid API key required", "invalid API key")

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Previous != prior {
		t.Errorf("Expected Previous to point to prior AuthContext, got %v", ctx.SharedContext.AuthContext.Previous)
	}
}
