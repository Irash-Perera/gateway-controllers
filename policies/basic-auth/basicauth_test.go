package basicauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	policyv1alpha "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func newBasicRequestContext(headers map[string][]string) *policyv1alpha.RequestContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policyv1alpha.RequestContext{
		SharedContext: &policyv1alpha.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: policyv1alpha.NewHeaders(headers),
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
	want := policyv1alpha.ProcessingMode{
		RequestHeaderMode:  policyv1alpha.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha.BodyModeSkip,
		ResponseHeaderMode: policyv1alpha.HeaderModeSkip,
		ResponseBodyMode:   policyv1alpha.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestGetPolicy_ReturnsSingleton(t *testing.T) {
	p1, err := GetPolicy(policyv1alpha.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	p2, err := GetPolicy(policyv1alpha.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestBasicAuthPolicy_OnRequest_ValidCredentials(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestContext(map[string][]string{
		"authorization": {basicAuthHeader("admin", "secret")},
	})

	action := p.OnRequest(ctx, defaultParams())

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
	if _, ok := action.(policyv1alpha.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestBasicAuthPolicy_OnRequest_WrongPassword(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestContext(map[string][]string{
		"authorization": {basicAuthHeader("admin", "wrong-password")},
	})

	action := p.OnRequest(ctx, defaultParams())

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=false for wrong password")
	}
	if ctx.SharedContext.AuthContext.AuthType != "basic" {
		t.Errorf("expected AuthType='basic', got %q", ctx.SharedContext.AuthContext.AuthType)
	}

	resp, ok := action.(policyv1alpha.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestBasicAuthPolicy_OnRequest_MissingAuthorizationHeader(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestContext(nil)

	action := p.OnRequest(ctx, defaultParams())

	resp, ok := action.(policyv1alpha.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
	assertJSONError(t, resp.Body)
}

func TestBasicAuthPolicy_OnRequest_MalformedAuthorizationHeader(t *testing.T) {
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
			ctx := newBasicRequestContext(map[string][]string{
				"authorization": {tt.header},
			})

			action := p.OnRequest(ctx, defaultParams())

			if ctx.SharedContext.AuthContext == nil {
				t.Fatal("expected AuthContext to be set on failure")
			}
			if ctx.SharedContext.AuthContext.Authenticated {
				t.Error("expected Authenticated=false")
			}

			resp, ok := action.(policyv1alpha.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if resp.StatusCode != 401 {
				t.Errorf("expected status 401, got %d", resp.StatusCode)
			}
		})
	}
}

func TestBasicAuthPolicy_OnRequest_AllowUnauthenticated(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestContext(nil) // no authorization header

	params := map[string]interface{}{
		"username":             "admin",
		"password":             "secret",
		"allowUnauthenticated": true,
	}

	action := p.OnRequest(ctx, params)

	// Should allow through even without credentials
	if _, ok := action.(policyv1alpha.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications (allow through), got %T", action)
	}
	// AuthContext should still reflect the failure
	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=false even when allowUnauthenticated=true")
	}
}

func TestBasicAuthPolicy_OnRequest_CustomRealm(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestContext(nil)

	params := map[string]interface{}{
		"username": "admin",
		"password": "secret",
		"realm":    "My API",
	}

	action := p.OnRequest(ctx, params)

	resp, ok := action.(policyv1alpha.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	wwwAuth := resp.Headers["www-authenticate"]
	expected := fmt.Sprintf(`Basic realm="My API"`)
	if wwwAuth != expected {
		t.Errorf("expected WWW-Authenticate=%q, got %q", expected, wwwAuth)
	}
}

func TestBasicAuthPolicy_OnRequest_InvalidConfig_NoUsername(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestContext(nil)

	params := map[string]interface{}{
		"password": "secret",
	}

	action := p.OnRequest(ctx, params)

	resp, ok := action.(policyv1alpha.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500 for invalid config, got %d", resp.StatusCode)
	}
}

func TestBasicAuthPolicy_OnRequest_InvalidConfig_NoPassword(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := newBasicRequestContext(nil)

	params := map[string]interface{}{
		"username": "admin",
	}

	action := p.OnRequest(ctx, params)

	resp, ok := action.(policyv1alpha.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500 for invalid config, got %d", resp.StatusCode)
	}
}

func TestBasicAuthPolicy_OnResponse_NoOp(t *testing.T) {
	p := &BasicAuthPolicy{}
	action := p.OnResponse(&policyv1alpha.ResponseContext{}, nil)
	if action != nil {
		t.Fatalf("expected nil response action, got %T", action)
	}
}

func TestBasicAuthPolicy_AuthContext_PreviousPreserved_OnSuccess(t *testing.T) {
	p := &BasicAuthPolicy{}
	prior := &policyv1alpha.AuthContext{Authenticated: true, AuthType: "other"}
	ctx := newBasicRequestContext(nil)
	ctx.SharedContext.AuthContext = prior

	p.handleAuthSuccess(ctx, "alice")

	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set")
	}
	if ctx.SharedContext.AuthContext.Previous != prior {
		t.Errorf("Expected Previous to point to prior AuthContext, got %v", ctx.SharedContext.AuthContext.Previous)
	}
}

func TestBasicAuthPolicy_AuthContext_PreviousPreserved_OnFailure(t *testing.T) {
	p := &BasicAuthPolicy{}
	prior := &policyv1alpha.AuthContext{Authenticated: true, AuthType: "other"}
	ctx := newBasicRequestContext(nil)
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
