package basicauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func newBasicRequestHeaderContext(headers map[string][]string) *policyv1alpha2.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: policyv1alpha2.NewHeaders(headers),
		Method:  "GET",
		Path:    "/api/resource",
	}
}

func basicAuthHeader(username, password string) string {
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + creds
}

func defaultParams() map[string]interface{} {
	return map[string]interface{}{
		"username": "admin",
		"password": "secret",
	}
}

func TestBasicAuthPolicy_Mode(t *testing.T) {
	p := &BasicAuthPolicy{}
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
	p1, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicyV2 failed: %v", err)
	}
	p2, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicyV2 failed: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_ValidCredentials(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(map[string][]string{
		"authorization": {basicAuthHeader("admin", "secret")},
	})

	action := p.OnRequestHeaders(ctx, defaultParams())

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if !ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=true")
	}
	if ctx.SharedContext.AuthContext.AuthType != "basic" {
		t.Errorf("expected AuthType='basic', got %q", ctx.SharedContext.AuthContext.AuthType)
	}
	if ctx.SharedContext.AuthContext.Subject != "admin" {
		t.Errorf("expected Subject='admin', got %q", ctx.SharedContext.AuthContext.Subject)
	}
	if _, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_WrongPassword(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(map[string][]string{
		"authorization": {basicAuthHeader("admin", "wrong-password")},
	})

	action := p.OnRequestHeaders(ctx, defaultParams())

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=false for wrong password")
	}
	if ctx.SharedContext.AuthContext.AuthType != "basic" {
		t.Errorf("expected AuthType='basic', got %q", ctx.SharedContext.AuthContext.AuthType)
	}

	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_MissingAuthorizationHeader(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	action := p.OnRequestHeaders(ctx, defaultParams())

	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
	assertJSONError(t, resp.Body)
}

func TestBasicAuthPolicy_OnRequestHeaders_MalformedAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"not basic scheme", "Bearer some-token"},
		{"no space after Basic", "Basicadmin:secret"},
		{"invalid base64", "Basic !!!not-base64!!!"},
		{"no colon separator", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BasicAuthPolicy{}
			ctx := newBasicRequestHeaderContext(map[string][]string{
				"authorization": {tt.header},
			})

			action := p.OnRequestHeaders(ctx, defaultParams())

			if ctx.SharedContext.AuthContext == nil {
				t.Fatal("expected AuthContext to be set on failure")
			}
			if ctx.SharedContext.AuthContext.Authenticated {
				t.Error("expected Authenticated=false")
			}

			resp, ok := action.(policyv1alpha2.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if resp.StatusCode != 401 {
				t.Errorf("expected status 401, got %d", resp.StatusCode)
			}
		})
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_AllowUnauthenticated(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil) // no authorization header

	params := map[string]interface{}{
		"username":             "admin",
		"password":             "secret",
		"allowUnauthenticated": true,
	}

	action := p.OnRequestHeaders(ctx, params)

	// Should allow through even without credentials
	if _, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications (allow through), got %T", action)
	}
	// AuthContext should still reflect the failure
	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=false even when allowUnauthenticated=true")
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_CustomRealm(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	params := map[string]interface{}{
		"username": "admin",
		"password": "secret",
		"realm":    "My API",
	}

	action := p.OnRequestHeaders(ctx, params)

	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	wwwAuth := resp.Headers["www-authenticate"]
	expected := fmt.Sprintf(`Basic realm="My API"`)
	if wwwAuth != expected {
		t.Errorf("expected WWW-Authenticate=%q, got %q", expected, wwwAuth)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_InvalidConfig_NoUsername(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	params := map[string]interface{}{
		"password": "secret",
	}

	action := p.OnRequestHeaders(ctx, params)

	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500 for invalid config, got %d", resp.StatusCode)
	}
}

func TestBasicAuthPolicy_OnRequestHeaders_InvalidConfig_NoPassword(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestHeaderContext(nil)

	params := map[string]interface{}{
		"username": "admin",
	}

	action := p.OnRequestHeaders(ctx, params)

	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500 for invalid config, got %d", resp.StatusCode)
	}
}

// TestBasicAuthPolicy_AuthContext_PreviousPreserved_OnSuccess tests the v1alpha helper
// that chains AuthContext entries.
func TestBasicAuthPolicy_AuthContext_PreviousPreserved_OnSuccess(t *testing.T) {
	p := &BasicAuthPolicy{}
	prior := &policy.AuthContext{Authenticated: true, AuthType: "other"}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: policy.NewHeaders(nil),
		Method:  "GET",
		Path:    "/api/resource",
	}
	ctx.SharedContext.AuthContext = prior

	p.handleAuthSuccess(ctx, "alice")

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Previous != prior {
		t.Errorf("Expected Previous to point to prior AuthContext, got %v", ctx.SharedContext.AuthContext.Previous)
	}
}

// TestBasicAuthPolicy_AuthContext_PreviousPreserved_OnFailure tests the v1alpha helper
// that chains AuthContext entries on failure.
func TestBasicAuthPolicy_AuthContext_PreviousPreserved_OnFailure(t *testing.T) {
	p := &BasicAuthPolicy{}
	prior := &policy.AuthContext{Authenticated: true, AuthType: "other"}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: policy.NewHeaders(nil),
		Method:  "GET",
		Path:    "/api/resource",
	}
	ctx.SharedContext.AuthContext = prior

	p.handleAuthFailure(ctx, false, "Restricted", "invalid credentials")

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Previous != prior {
		t.Errorf("Expected Previous to point to prior AuthContext, got %v", ctx.SharedContext.AuthContext.Previous)
	}
}

func assertJSONError(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("expected JSON body, got: %s", string(body))
	}
	if result["error"] == "" {
		t.Error("expected non-empty 'error' field in JSON body")
	}
}
