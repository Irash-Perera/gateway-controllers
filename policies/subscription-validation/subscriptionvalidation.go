package subscriptionvalidation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	policyenginev1 "github.com/wso2/api-platform/sdk/gateway/policyengine/v1"
)

const (
	defaultSubscriptionKeyHeader = "Subscription-Key"
	defaultSubscriptionKeyCookie = ""
	applicationIDMetadataKey     = "x-wso2-application-id"
	forbiddenStatusCode          = 403
	forbiddenMessage             = "Subscription required for this API"

	// Eviction TTL: entries not seen in this duration are removed to prevent unbounded growth.
	rateLimitEvictionTTL     = 2 * time.Hour
	rateLimitCleanupInterval = 10 * time.Minute
)

// PolicyConfig holds the resolved configuration for the subscriptionValidation policy.
type PolicyConfig struct {
	SubscriptionKeyHeader string
	SubscriptionKeyCookie string
}

// rateLimitEntry tracks per-token request counts within a time window.
type rateLimitEntry struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time // used for TTL eviction
}

// SubscriptionValidationPolicy validates that the caller has an active
// subscription for the requested API and enforces plan-based rate limits.
type SubscriptionValidationPolicy struct {
	cfg   PolicyConfig
	store *policyenginev1.SubscriptionStore

	rateLimitMu *sync.Mutex
	rateLimits  map[string]*rateLimitEntry // key: "apiId:token"
}

var (
	sharedRateLimitMu = &sync.Mutex{}
	ins               = &SubscriptionValidationPolicy{
		cfg: PolicyConfig{
			SubscriptionKeyHeader: defaultSubscriptionKeyHeader,
			SubscriptionKeyCookie: defaultSubscriptionKeyCookie,
		},
		store:       policyenginev1.GetSubscriptionStoreInstance(),
		rateLimitMu: sharedRateLimitMu,
		rateLimits:  make(map[string]*rateLimitEntry),
	}
)

func init() {
	go runRateLimitCleaner()
}

// getCookieValue parses the Cookie header and returns the value for the given cookie name.
// Returns empty string if the cookie is not found or Cookie header is missing.
func getCookieValue(headers *policy.Headers, name string) string {
	if headers == nil || name == "" {
		return ""
	}
	vals := headers.Get("Cookie")
	if len(vals) == 0 {
		return ""
	}
	// Cookie header format: "name1=value1; name2=value2"
	for _, raw := range vals {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "=")
			if idx < 0 {
				continue
			}
			cookieName := strings.TrimSpace(part[:idx])
			if strings.EqualFold(cookieName, name) {
				return strings.TrimSpace(part[idx+1:])
			}
		}
	}
	return ""
}

// runRateLimitCleaner periodically evicts stale entries from the shared rateLimits map.
func runRateLimitCleaner() {
	ticker := time.NewTicker(rateLimitCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		ins.rateLimitMu.Lock()
		cutoff := time.Now().Add(-rateLimitEvictionTTL)
		for key, e := range ins.rateLimits {
			if e != nil && e.lastSeen.Before(cutoff) {
				delete(ins.rateLimits, key)
			}
		}
		ins.rateLimitMu.Unlock()
	}
}

// GetPolicy is the v1alpha factory entry point (loaded by v1alpha kernels).
// TODO: add GetPolicyV2 once this module is upgraded to sdk v0.4.5+ (ProcessingMode type alias required).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SubscriptionValidationPolicy{
		cfg:         mergeConfig(ins.cfg, params),
		store:       ins.store,
		rateLimitMu: ins.rateLimitMu,
		rateLimits:  ins.rateLimits,
	}
	return p, nil
}

// mergeConfig merges raw parameters from the policy configuration into a base config.
func mergeConfig(base PolicyConfig, params map[string]interface{}) PolicyConfig {
	cfg := base
	if params == nil {
		return cfg
	}

	if raw, ok := params["subscriptionKeyHeader"]; ok {
		if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
			cfg.SubscriptionKeyHeader = strings.TrimSpace(s)
		}
	}

	if raw, ok := params["subscriptionKeyCookie"]; ok {
		if s, ok := raw.(string); ok {
			cfg.SubscriptionKeyCookie = strings.TrimSpace(s)
		}
	}

	return cfg
}

// Mode returns the processing mode for this policy.
func (p *SubscriptionValidationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequest validates the subscription (token-first, appId-fallback)
// and enforces plan-based rate limiting when applicable.
func (p *SubscriptionValidationPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if ctx == nil || ctx.SharedContext == nil {
		return p.forbiddenResponse("request context is missing")
	}

	apiID := ctx.SharedContext.APIId
	if strings.TrimSpace(apiID) == "" {
		slog.Error("subscriptionValidation: APIId is empty in SharedContext; failing validation")
		return p.forbiddenResponse("API id is missing")
	}

	if p.store == nil {
		slog.Error("subscriptionValidation: subscription store is not initialized")
		return p.forbiddenResponse("subscription store is not available")
	}

	// Path 1: Check Subscription-Key header (token-based, primary)
	if ctx.Headers != nil {
		headerValues := ctx.Headers.Get(p.cfg.SubscriptionKeyHeader)
		if len(headerValues) > 0 {
			token := strings.TrimSpace(headerValues[0])
			if token != "" {
				if action := p.validateByToken(apiID, token); action != nil {
					return action
				}
				return policy.UpstreamRequestModifications{
					RemoveHeaders: []string{normalizeHeaderName(p.cfg.SubscriptionKeyHeader)},
				}
			}
		}
		// Path 1b: Check subscription key cookie if configured
		if p.cfg.SubscriptionKeyCookie != "" {
			if token := getCookieValue(ctx.Headers, p.cfg.SubscriptionKeyCookie); token != "" {
				if action := p.validateByToken(apiID, token); action != nil {
					return action
				}

				cookieValues := ctx.Headers.Get("Cookie")
				updated, removed := stripCookie(cookieValues, p.cfg.SubscriptionKeyCookie)
				if removed {
					if updated == "" {
						return policy.UpstreamRequestModifications{RemoveHeaders: []string{"cookie"}}
					}
					return policy.UpstreamRequestModifications{SetHeaders: map[string]string{"cookie": updated}}
				}

				// Token came from cookie lookup, but we couldn't safely strip it; fail open on stripping only.
				return policy.UpstreamRequestModifications{}
			}
		}
	}

	// Path 2: Fallback to application ID from auth metadata (legacy)
	metadata := ctx.SharedContext.Metadata
	if metadata != nil {
		if rawAppID, ok := metadata[applicationIDMetadataKey]; ok {
			appID := strings.TrimSpace(fmt.Sprint(rawAppID))
			if appID != "" {
				return p.validateByApplication(apiID, appID)
			}
		}
	}

	// Neither token nor application ID was provided
	return p.forbiddenResponse("no subscription token or application identity provided")
}

// validateByToken checks the token against the store, then enforces rate limits.
// The store uses hashed tokens; we hash the incoming token before lookup.
func (p *SubscriptionValidationPolicy) validateByToken(apiID, token string) policy.RequestAction {
	hashedToken := policyenginev1.HashSubscriptionToken(token)
	active, entry := p.store.IsActiveByToken(apiID, hashedToken)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (token)",
			"apiId", apiID)
		return p.forbiddenResponse("")
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimit(apiID, token, entry); blocked != nil {
			return blocked
		}
	}

	return nil
}

// validateByApplication checks the application ID against the store, then enforces rate limits.
// This is the legacy path; it now recovers quota/throttle metadata from the store.
func (p *SubscriptionValidationPolicy) validateByApplication(apiID, appID string) policy.RequestAction {
	active, entry := p.store.IsActiveByApplication(apiID, appID)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (appId fallback)",
			"apiId", apiID,
			"applicationId", appID)
		return p.forbiddenResponse("")
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimit(apiID, appID, entry); blocked != nil {
			return blocked
		}
	}

	return nil
}

// checkRateLimit enforces the plan's throttle limit for the given token.
func (p *SubscriptionValidationPolicy) checkRateLimit(apiID, token string, entry *policyenginev1.SubscriptionEntry) policy.RequestAction {
	window := windowDuration(entry.ThrottleLimitUnit)
	if window == 0 {
		return nil
	}

	key := apiID + ":" + token
	now := time.Now()

	p.rateLimitMu.Lock()
	rl, exists := p.rateLimits[key]
	if !exists || now.Sub(rl.windowStart) >= window {
		p.rateLimits[key] = &rateLimitEntry{windowStart: now, count: 1, lastSeen: now}
		p.rateLimitMu.Unlock()
		return nil
	}

	rl.count++
	rl.lastSeen = now
	exceeded := rl.count > entry.ThrottleLimitCount
	resetAt := rl.windowStart.Add(window)
	limit := entry.ThrottleLimitCount
	remaining := limit - rl.count
	if remaining < 0 {
		remaining = 0
	}
	p.rateLimitMu.Unlock()

	if exceeded {
		if entry.StopOnQuotaReach {
			return p.rateLimitResponse(limit, remaining, resetAt, window)
		}
		slog.Warn("subscriptionValidation: quota exceeded but stopOnQuotaReach is false, allowing",
			"apiId", apiID)
	}

	return nil
}

// windowDuration converts a throttle unit string to a time.Duration.
func windowDuration(unit string) time.Duration {
	switch strings.ToLower(unit) {
	case "min":
		return time.Minute
	case "hour":
		return time.Hour
	case "day":
		return 24 * time.Hour
	case "month":
		return 30 * 24 * time.Hour
	default:
		return 0
	}
}

// OnResponse is a no-op for this policy.
func (p *SubscriptionValidationPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return nil
}

// forbiddenResponse constructs an ImmediateResponse with status 403.
func (p *SubscriptionValidationPolicy) forbiddenResponse(detail string) policy.RequestAction {
	message := forbiddenMessage
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	payload := map[string]string{
		"error":   "forbidden",
		"message": message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"forbidden","message":"subscription validation failed"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: forbiddenStatusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}
}

// rateLimitResponse constructs a 429 Too Many Requests response.
func (p *SubscriptionValidationPolicy) rateLimitResponse(limit, remaining int, resetAt time.Time, window time.Duration) policy.RequestAction {
	payload := map[string]interface{}{
		"error":   "rate_limit_exceeded",
		"message": fmt.Sprintf("Subscription quota exceeded: %d requests per %s", limit, entryThrottleUnitString(window)),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"rate_limit_exceeded","message":"subscription quota exceeded"}`)
	}

	resetUnix := resetAt.Unix()
	resetSeconds := int64(time.Until(resetAt).Seconds())
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	retryAfterSeconds := resetSeconds
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	windowSeconds := int64(window.Seconds())
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	policyValue := fmt.Sprintf("%d;w=%d", limit, windowSeconds)

	return policy.ImmediateResponse{
		StatusCode: 429,
		Headers: map[string]string{
			"Content-Type": "application/json",
			// X-RateLimit-* (de facto standard)
			"X-RateLimit-Limit":            strconv.Itoa(limit),
			"X-RateLimit-Remaining":        strconv.Itoa(remaining),
			"X-RateLimit-Reset":            strconv.FormatInt(resetUnix, 10),
			"X-RateLimit-Full-Quota-Reset": strconv.FormatInt(resetUnix, 10),
			// RateLimit-* (IETF draft)
			"RateLimit-Limit":            strconv.Itoa(limit),
			"RateLimit-Remaining":        strconv.Itoa(remaining),
			"RateLimit-Reset":            strconv.FormatInt(resetSeconds, 10),
			"RateLimit-Full-Quota-Reset": strconv.FormatInt(resetSeconds, 10),
			"RateLimit-Policy":           policyValue,
			// RFC 7231
			"Retry-After": strconv.FormatInt(retryAfterSeconds, 10),
		},
		Body: body,
	}
}

// entryThrottleUnitString returns a human-friendly unit string for the throttling window.
// We avoid exposing the exact unit parsing logic externally.
func entryThrottleUnitString(window time.Duration) string {
	switch window {
	case time.Minute:
		return "Min"
	case time.Hour:
		return "Hour"
	case 24 * time.Hour:
		return "Day"
	default:
		return window.String()
	}
}

func normalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// stripCookie removes the cookie with the given name from Cookie header values.
// It returns the updated Cookie header (single header value) and whether a removal occurred.
func stripCookie(cookieHeaderValues []string, cookieName string) (string, bool) {
	if cookieName == "" || len(cookieHeaderValues) == 0 {
		return "", false
	}

	parts := make([]string, 0, 8)
	removed := false

	for _, raw := range cookieHeaderValues {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "=")
			if idx < 0 {
				parts = append(parts, part)
				continue
			}
			name := strings.TrimSpace(part[:idx])
			if strings.EqualFold(name, cookieName) {
				removed = true
				continue
			}
			parts = append(parts, part)
		}
	}

	if !removed {
		return "", false
	}
	return strings.Join(parts, "; "), true
}

// OnRequestHeaders validates the subscription in the request header phase.
func (p *SubscriptionValidationPolicy) OnRequestHeaders(ctx *policyv1alpha2.RequestHeaderContext, params map[string]interface{}) policyv1alpha2.RequestHeaderAction {
	if ctx == nil || ctx.SharedContext == nil {
		return p.forbiddenResponseV2("request context is missing").(policyv1alpha2.ImmediateResponse)
	}

	apiID := ctx.SharedContext.APIId
	if strings.TrimSpace(apiID) == "" {
		slog.Error("subscriptionValidation: APIId is empty in SharedContext; failing validation")
		return p.forbiddenResponseV2("API id is missing").(policyv1alpha2.ImmediateResponse)
	}

	if p.store == nil {
		slog.Error("subscriptionValidation: subscription store is not initialized")
		return p.forbiddenResponseV2("subscription store is not available").(policyv1alpha2.ImmediateResponse)
	}

	if ctx.Headers != nil {
		headerValues := ctx.Headers.Get(p.cfg.SubscriptionKeyHeader)
		if len(headerValues) > 0 {
			token := strings.TrimSpace(headerValues[0])
			if token != "" {
				result := p.validateByTokenV2(apiID, token)
				if result == nil {
					return policyv1alpha2.UpstreamRequestHeaderModifications{
						HeadersToRemove: []string{normalizeHeaderName(p.cfg.SubscriptionKeyHeader)},
					}
				}
				return result.(policyv1alpha2.ImmediateResponse)
			}
		}
		if p.cfg.SubscriptionKeyCookie != "" {
			if token := getCookieValueV2(ctx.Headers, p.cfg.SubscriptionKeyCookie); token != "" {
				result := p.validateByTokenV2(apiID, token)
				if result == nil {
					cookieValues := ctx.Headers.Get("Cookie")
					updated, removed := stripCookie(cookieValues, p.cfg.SubscriptionKeyCookie)
					if removed {
						if updated == "" {
							return policyv1alpha2.UpstreamRequestHeaderModifications{
								HeadersToRemove: []string{"cookie"},
							}
						}
						return policyv1alpha2.UpstreamRequestHeaderModifications{
							HeadersToSet: map[string]string{"cookie": updated},
						}
					}
					return policyv1alpha2.UpstreamRequestHeaderModifications{}
				}
				return result.(policyv1alpha2.ImmediateResponse)
			}
		}
	}

	metadata := ctx.SharedContext.Metadata
	if metadata != nil {
		if rawAppID, ok := metadata[applicationIDMetadataKey]; ok {
			appID := strings.TrimSpace(fmt.Sprint(rawAppID))
			if appID != "" {
				result := p.validateByApplicationV2(apiID, appID)
				if result == nil {
					return policyv1alpha2.UpstreamRequestHeaderModifications{}
				}
				return result.(policyv1alpha2.ImmediateResponse)
			}
		}
	}

	return p.forbiddenResponseV2("no subscription token or application identity provided").(policyv1alpha2.ImmediateResponse)
}

// forbiddenResponse constructs an ImmediateResponse with status 403.
func (p *SubscriptionValidationPolicy) forbiddenResponseV2(detail string) policyv1alpha2.RequestAction {
	message := forbiddenMessage
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	payload := map[string]string{
		"error":   "forbidden",
		"message": message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"forbidden","message":"subscription validation failed"}`)
	}

	return policyv1alpha2.ImmediateResponse{
		StatusCode: forbiddenStatusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}
}

// validateByToken checks the token against the store, then enforces rate limits.
// The store uses hashed tokens; we hash the incoming token before lookup.
func (p *SubscriptionValidationPolicy) validateByTokenV2(apiID, token string) policyv1alpha2.RequestAction {
	hashedToken := policyenginev1.HashSubscriptionToken(token)
	active, entry := p.store.IsActiveByToken(apiID, hashedToken)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (token)",
			"apiId", apiID)
		return p.forbiddenResponseV2("")
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimitV2(apiID, token, entry); blocked != nil {
			return blocked
		}
	}

	return nil
}

// checkRateLimit enforces the plan's throttle limit for the given token.
func (p *SubscriptionValidationPolicy) checkRateLimitV2(apiID, token string, entry *policyenginev1.SubscriptionEntry) policyv1alpha2.RequestAction {
	window := windowDuration(entry.ThrottleLimitUnit)
	if window == 0 {
		return nil
	}

	key := apiID + ":" + token
	now := time.Now()

	p.rateLimitMu.Lock()
	rl, exists := p.rateLimits[key]
	if !exists || now.Sub(rl.windowStart) >= window {
		p.rateLimits[key] = &rateLimitEntry{windowStart: now, count: 1, lastSeen: now}
		p.rateLimitMu.Unlock()
		return nil
	}

	rl.count++
	rl.lastSeen = now
	exceeded := rl.count > entry.ThrottleLimitCount
	resetAt := rl.windowStart.Add(window)
	limit := entry.ThrottleLimitCount
	remaining := limit - rl.count
	if remaining < 0 {
		remaining = 0
	}
	p.rateLimitMu.Unlock()

	if exceeded {
		if entry.StopOnQuotaReach {
			return p.rateLimitResponseV2(limit, remaining, resetAt, window)
		}
		slog.Warn("subscriptionValidation: quota exceeded but stopOnQuotaReach is false, allowing",
			"apiId", apiID)
	}

	return nil
}

// validateByApplication checks the application ID against the store, then enforces rate limits.
// This is the legacy path; it now recovers quota/throttle metadata from the store.
func (p *SubscriptionValidationPolicy) validateByApplicationV2(apiID, appID string) policyv1alpha2.RequestAction {
	active, entry := p.store.IsActiveByApplication(apiID, appID)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (appId fallback)",
			"apiId", apiID,
			"applicationId", appID)
		return p.forbiddenResponseV2("")
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimitV2(apiID, appID, entry); blocked != nil {
			return blocked
		}
	}

	return nil
}

// getCookieValue parses the Cookie header and returns the value for the given cookie name.
// Returns empty string if the cookie is not found or Cookie header is missing.
func getCookieValueV2(headers *policyv1alpha2.Headers, name string) string {
	if headers == nil || name == "" {
		return ""
	}
	vals := headers.Get("Cookie")
	if len(vals) == 0 {
		return ""
	}
	// Cookie header format: "name1=value1; name2=value2"
	for _, raw := range vals {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "=")
			if idx < 0 {
				continue
			}
			cookieName := strings.TrimSpace(part[:idx])
			if strings.EqualFold(cookieName, name) {
				return strings.TrimSpace(part[idx+1:])
			}
		}
	}
	return ""
}

// rateLimitResponse constructs a 429 Too Many Requests response.
func (p *SubscriptionValidationPolicy) rateLimitResponseV2(limit, remaining int, resetAt time.Time, window time.Duration) policyv1alpha2.RequestAction {
	payload := map[string]interface{}{
		"error":   "rate_limit_exceeded",
		"message": fmt.Sprintf("Subscription quota exceeded: %d requests per %s", limit, entryThrottleUnitString(window)),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"rate_limit_exceeded","message":"subscription quota exceeded"}`)
	}

	resetUnix := resetAt.Unix()
	resetSeconds := int64(time.Until(resetAt).Seconds())
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	retryAfterSeconds := resetSeconds
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	windowSeconds := int64(window.Seconds())
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	policyValue := fmt.Sprintf("%d;w=%d", limit, windowSeconds)

	return policyv1alpha2.ImmediateResponse{
		StatusCode: 429,
		Headers: map[string]string{
			"Content-Type": "application/json",
			// X-RateLimit-* (de facto standard)
			"X-RateLimit-Limit":            strconv.Itoa(limit),
			"X-RateLimit-Remaining":        strconv.Itoa(remaining),
			"X-RateLimit-Reset":            strconv.FormatInt(resetUnix, 10),
			"X-RateLimit-Full-Quota-Reset": strconv.FormatInt(resetUnix, 10),
			// RateLimit-* (IETF draft)
			"RateLimit-Limit":            strconv.Itoa(limit),
			"RateLimit-Remaining":        strconv.Itoa(remaining),
			"RateLimit-Reset":            strconv.FormatInt(resetSeconds, 10),
			"RateLimit-Full-Quota-Reset": strconv.FormatInt(resetSeconds, 10),
			"RateLimit-Policy":           policyValue,
			// RFC 7231
			"Retry-After": strconv.FormatInt(retryAfterSeconds, 10),
		},
		Body: body,
	}
}