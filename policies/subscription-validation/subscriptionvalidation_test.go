package subscriptionvalidation

import (
	"encoding/json"
	"strconv"
	"testing"
	"strings"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policyenginev1 "github.com/wso2/api-platform/sdk/gateway/policyengine/v1"
)

// --- helpers -----------------------------------------------------------------

func newStore(entries []policyenginev1.SubscriptionData) *policyenginev1.SubscriptionStore {
	s := policyenginev1.NewSubscriptionStore()
	s.ReplaceAll(entries)
	return s
}

func newPolicy(cfg PolicyConfig, store *policyenginev1.SubscriptionStore) *SubscriptionValidationPolicy {
	return &SubscriptionValidationPolicy{
		cfg:         cfg,
		store:       store,
		rateLimitMu: sharedRateLimitMu,
		rateLimits:  make(map[string]*rateLimitEntry),
	}
}

func defaultCfg() PolicyConfig {
	return PolicyConfig{
		SubscriptionKeyHeader: defaultSubscriptionKeyHeader,
		SubscriptionKeyCookie: defaultSubscriptionKeyCookie,
	}
}

func headerCtxWithToken(apiID, token, headerName string) *policyv1alpha2.RequestHeaderContext {
	if headerName == "" {
		headerName = defaultSubscriptionKeyHeader
	}
	return &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			APIId:    apiID,
			Metadata: map[string]interface{}{},
		},
		Headers: policyv1alpha2.NewHeaders(map[string][]string{
			headerName: {token},
		}),
	}
}

func headerCtxWithAppID(apiID, appID string) *policyv1alpha2.RequestHeaderContext {
	return &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			APIId: apiID,
			Metadata: map[string]interface{}{
				applicationIDMetadataKey: appID,
			},
		},
		Headers: policyv1alpha2.NewHeaders(nil),
	}
}

func headerCtxWithCookie(apiID, token, cookieName string) *policyv1alpha2.RequestHeaderContext {
	return &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			APIId:    apiID,
			Metadata: map[string]interface{}{},
		},
		Headers: policyv1alpha2.NewHeaders(map[string][]string{
			"Cookie": {cookieName + "=" + token},
		}),
	}
}

func assertSuccess(t *testing.T, action policyv1alpha2.RequestHeaderAction) {
	t.Helper()
	if _, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications (allow), got %#v", action)
	}
}

func assertHeaderRemoved(t *testing.T, action policyv1alpha2.RequestHeaderAction, header string) {
	t.Helper()
	mod, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %#v", action)
	}
	header = strings.ToLower(strings.TrimSpace(header))
	for _, h := range mod.HeadersToRemove {
		if strings.ToLower(strings.TrimSpace(h)) == header {
			return
		}
	}
	t.Fatalf("expected header %q to be removed; got HeadersToRemove=%v", header, mod.HeadersToRemove)
}

func assertCookieStripped(t *testing.T, action policyv1alpha2.RequestHeaderAction, cookieName string) {
	t.Helper()
	mod, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %#v", action)
	}
	// Either Cookie is fully removed...
	for _, h := range mod.HeadersToRemove {
		if strings.EqualFold(strings.TrimSpace(h), "cookie") {
			return
		}
	}
	// ...or rewritten without the cookieName.
	cookieHeader, ok := mod.HeadersToSet["cookie"]
	if !ok {
		cookieHeader, ok = mod.HeadersToSet["Cookie"]
	}
	if !ok {
		t.Fatalf("expected cookie to be removed or rewritten; got HeadersToRemove=%v HeadersToSet=%v", mod.HeadersToRemove, mod.HeadersToSet)
	}
	if strings.Contains(strings.ToLower(cookieHeader), strings.ToLower(cookieName)+"=") {
		t.Fatalf("expected cookie %q to be stripped; got Cookie header %q", cookieName, cookieHeader)
	}
}

func assertImmediate(t *testing.T, action policyv1alpha2.RequestHeaderAction, wantStatus int, wantErrorKey string) {
	t.Helper()
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("expected status %d, got %d", wantStatus, resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if body["error"] != wantErrorKey {
		t.Fatalf("expected error=%q, got %q", wantErrorKey, body["error"])
	}
}

func assertRateLimitHeaders(t *testing.T, resp policyv1alpha2.ImmediateResponse, wantLimit, wantRemaining int) {
	t.Helper()
	if resp.Headers == nil {
		t.Fatalf("expected headers to be set")
	}
	assertIntHeader := func(key string, want int) {
		gotRaw, ok := resp.Headers[key]
		if !ok {
			t.Fatalf("missing rate-limit header %q", key)
		}
		got, err := strconv.Atoi(gotRaw)
		if err != nil {
			t.Fatalf("rate-limit header %q value %q is not an int: %v", key, gotRaw, err)
		}
		if got != want {
			t.Fatalf("rate-limit header %q expected %d, got %d", key, want, got)
		}
	}

	if ct, ok := resp.Headers["Content-Type"]; !ok || ct != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %q (ok=%v)", ct, ok)
	}

	assertIntHeader("X-RateLimit-Limit", wantLimit)
	assertIntHeader("X-RateLimit-Remaining", wantRemaining)
	assertIntHeader("RateLimit-Limit", wantLimit)
	assertIntHeader("RateLimit-Remaining", wantRemaining)

	// Reset-related headers can be time-sensitive; assert they are present and parse.
	parseInt64Header := func(key string) int64 {
		gotRaw, ok := resp.Headers[key]
		if !ok {
			t.Fatalf("missing rate-limit header %q", key)
		}
		got, err := strconv.ParseInt(gotRaw, 10, 64)
		if err != nil {
			t.Fatalf("rate-limit header %q value %q is not an int64: %v", key, gotRaw, err)
		}
		return got
	}

	xResetUnix := parseInt64Header("X-RateLimit-Reset")
	if xResetUnix < 0 {
		t.Fatalf("expected X-RateLimit-Reset >= 0, got %d", xResetUnix)
	}
	_ = parseInt64Header("X-RateLimit-Full-Quota-Reset")

	rResetSeconds := parseInt64Header("RateLimit-Reset")
	if rResetSeconds < 0 {
		t.Fatalf("expected RateLimit-Reset >= 0, got %d", rResetSeconds)
	}
	_ = parseInt64Header("RateLimit-Full-Quota-Reset")

	if policyValue, ok := resp.Headers["RateLimit-Policy"]; !ok || policyValue == "" {
		t.Fatalf("missing/empty rate-limit header %q", "RateLimit-Policy")
	}

	retryAfter := parseInt64Header("Retry-After")
	if retryAfter < 1 {
		t.Fatalf("expected Retry-After >= 1, got %d", retryAfter)
	}
}

// --- mergeConfig tests -------------------------------------------------------

func TestMergeConfig_Defaults(t *testing.T) {
	cfg := mergeConfig(defaultCfg(), nil)
	if cfg.SubscriptionKeyHeader != defaultSubscriptionKeyHeader {
		t.Fatalf("expected default header=%q, got %q", defaultSubscriptionKeyHeader, cfg.SubscriptionKeyHeader)
	}
}

func TestMergeConfig_Overrides(t *testing.T) {
	cfg := mergeConfig(defaultCfg(), map[string]interface{}{
		"subscriptionKeyHeader": "X-My-Key",
		"subscriptionKeyCookie": "sub-key",
	})
	if cfg.SubscriptionKeyHeader != "X-My-Key" {
		t.Fatalf("expected header=X-My-Key, got %q", cfg.SubscriptionKeyHeader)
	}
	if cfg.SubscriptionKeyCookie != "sub-key" {
		t.Fatalf("expected cookie=sub-key, got %q", cfg.SubscriptionKeyCookie)
	}
}

// --- token path (primary) ----------------------------------------------------

func TestOnRequestHeaders_AllowsValidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	action := p.OnRequestHeaders(ctx, nil)
	assertSuccess(t, action)
	assertHeaderRemoved(t, action, defaultSubscriptionKeyHeader)
}

func TestOnRequestHeaders_DeniesInvalidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "wrong-token", "")
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}

func TestOnRequestHeaders_DeniesInactiveToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "INACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}

func TestOnRequestHeaders_CustomHeaderName(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyHeader = "X-Custom-Sub"
	p := newPolicy(cfg, store)

	ctx := headerCtxWithToken("api-1", "tok-1", "X-Custom-Sub")
	action := p.OnRequestHeaders(ctx, nil)
	assertSuccess(t, action)
	assertHeaderRemoved(t, action, "X-Custom-Sub")
}

// --- cookie path -------------------------------------------------------------

func TestOnRequestHeaders_AllowsValidTokenFromCookie(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := headerCtxWithCookie("api-1", "tok-1", "sub-key")
	action := p.OnRequestHeaders(ctx, nil)
	assertSuccess(t, action)
	assertCookieStripped(t, action, "sub-key")
}

func TestOnRequestHeaders_CookieDeniesInvalidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := headerCtxWithCookie("api-1", "wrong-token", "sub-key")
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}

func TestOnRequestHeaders_HeaderTakesPrecedenceOverCookie(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			APIId:    "api-1",
			Metadata: map[string]interface{}{},
		},
		Headers: policyv1alpha2.NewHeaders(map[string][]string{
			defaultSubscriptionKeyHeader: {"tok-1"},
			"Cookie":                    {"sub-key=wrong-token"},
		}),
	}
	// Header value should be used; tok-1 is valid
	action := p.OnRequestHeaders(ctx, nil)
	assertSuccess(t, action)
	assertHeaderRemoved(t, action, defaultSubscriptionKeyHeader)
}

func TestOnRequestHeaders_CookieUsedWhenHeaderMissing(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := headerCtxWithCookie("api-1", "tok-1", "sub-key")
	action := p.OnRequestHeaders(ctx, nil)
	assertSuccess(t, action)
	assertCookieStripped(t, action, "sub-key")
}

func TestGetCookieValueV2(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		cookie  string
		want    string
	}{
		{"single cookie", map[string][]string{"Cookie": {"sub-key=tok-1"}}, "sub-key", "tok-1"},
		{"multiple cookies", map[string][]string{"Cookie": {"a=1; sub-key=tok-1; b=2"}}, "sub-key", "tok-1"},
		{"missing cookie", map[string][]string{"Cookie": {"other=val"}}, "sub-key", ""},
		{"no cookie header", map[string][]string{}, "sub-key", ""},
		{"case insensitive name", map[string][]string{"Cookie": {"Sub-Key=tok-1"}}, "sub-key", "tok-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := policyv1alpha2.NewHeaders(tt.headers)
			got := getCookieValueV2(h, tt.cookie)
			if got != tt.want {
				t.Fatalf("getCookieValueV2(%q) = %q, want %q", tt.cookie, got, tt.want)
			}
		})
	}
}

// --- appId fallback (legacy) -------------------------------------------------

func TestOnRequestHeaders_FallbackAppIdAllows(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithAppID("api-1", "app-1")
	assertSuccess(t, p.OnRequestHeaders(ctx, nil))
}

func TestOnRequestHeaders_FallbackAppIdDenies(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithAppID("api-1", "app-wrong")
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}

// --- no identity at all ------------------------------------------------------

func TestOnRequestHeaders_DeniesWhenNoIdentity(t *testing.T) {
	store := newStore(nil)
	p := newPolicy(defaultCfg(), store)
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			APIId:    "api-1",
			Metadata: map[string]interface{}{},
		},
		Headers: policyv1alpha2.NewHeaders(nil),
	}
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}

// --- missing apiId fails closed ----------------------------------------------

func TestOnRequestHeaders_FailsClosedWhenAPIIdMissing(t *testing.T) {
	store := newStore(nil)
	p := newPolicy(defaultCfg(), store)
	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			APIId:    "",
			Metadata: map[string]interface{}{},
		},
		Headers: policyv1alpha2.NewHeaders(nil),
	}
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}

// --- rate limiting -----------------------------------------------------------

func TestOnRequestHeaders_RateLimitEnforced(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:              "api-1",
			SubscriptionToken:  policyenginev1.HashSubscriptionToken("tok-1"),
			Status:             "ACTIVE",
			ThrottleLimitCount: 3,
			ThrottleLimitUnit:  "Min",
			StopOnQuotaReach:   true,
		},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 3; i++ {
		ctx := headerCtxWithToken("api-1", "tok-1", "")
		action := p.OnRequestHeaders(ctx, nil)
		assertSuccess(t, action)
		assertHeaderRemoved(t, action, defaultSubscriptionKeyHeader)
	}

	ctx := headerCtxWithToken("api-1", "tok-1", "")
	action := p.OnRequestHeaders(ctx, nil)
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 429 {
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if body["error"] != "rate_limit_exceeded" {
		t.Fatalf("expected error=%q, got %q", "rate_limit_exceeded", body["error"])
	}
	assertRateLimitHeaders(t, resp, 3, 0)
}

func TestOnRequestHeaders_RateLimitNotEnforcedWhenStopOnQuotaFalse(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:              "api-1",
			SubscriptionToken:  policyenginev1.HashSubscriptionToken("tok-1"),
			Status:             "ACTIVE",
			ThrottleLimitCount: 1,
			ThrottleLimitUnit:  "Min",
			StopOnQuotaReach:   false,
		},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 5; i++ {
		ctx := headerCtxWithToken("api-1", "tok-1", "")
		action := p.OnRequestHeaders(ctx, nil)
		if _, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("request %d should be allowed (stopOnQuotaReach=false), got %#v", i+1, action)
		}
	}
}

func TestOnRequestHeaders_NoRateLimitWithoutPlan(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 100; i++ {
		ctx := headerCtxWithToken("api-1", "tok-1", "")
		action := p.OnRequestHeaders(ctx, nil)
		if _, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("request %d should be allowed (no throttle plan), got %#v", i+1, action)
		}
	}
}

// --- token takes precedence over appId ---------------------------------------

func TestOnRequestHeaders_TokenTakesPrecedenceOverAppId(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)

	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: &policyv1alpha2.SharedContext{
			APIId: "api-1",
			Metadata: map[string]interface{}{
				applicationIDMetadataKey: "app-1",
			},
		},
		Headers: policyv1alpha2.NewHeaders(map[string][]string{
			defaultSubscriptionKeyHeader: {"wrong-token"},
		}),
	}
	// Token path should be tried first and should fail (wrong token),
	// even though appId path would succeed.
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}

// --- nil context / nil store guards ------------------------------------------

func TestOnRequestHeaders_NilContext(t *testing.T) {
	p := newPolicy(defaultCfg(), policyenginev1.NewSubscriptionStore())
	assertImmediate(t, p.OnRequestHeaders(nil, nil), 403, "forbidden")
}

func TestOnRequestHeaders_NilStore(t *testing.T) {
	p := newPolicy(defaultCfg(), nil)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	assertImmediate(t, p.OnRequestHeaders(ctx, nil), 403, "forbidden")
}
