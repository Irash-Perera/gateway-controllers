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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package responsecache

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	defaultTTL             = 60 * time.Second
	defaultMaxEntries      = 10000
	defaultCleanupInterval = time.Minute

	cacheKeyMetadataKey = "response_cache_key"
	cacheHitHeader      = "X-Cache-Status"
	cacheHitValue       = "HIT"
)

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-length":      {},
}

type ResponseCachePolicy struct {
	cache                *inMemoryCache
	ttl                  time.Duration
	cacheableStatusCodes map[int]struct{}
}

type cacheConfig struct {
	ttl                  time.Duration
	maxEntries           int
	cleanupInterval      time.Duration
	cacheableStatusCodes map[int]struct{}
}

type cachedResponse struct {
	statusCode      int
	headers         map[string]string
	body            []byte
	hasResponseBody bool
}

type cacheEntry struct {
	response   cachedResponse
	expiresAt  time.Time
	lastAccess time.Time
}

type inMemoryCache struct {
	mu              sync.RWMutex
	entries         map[string]cacheEntry
	maxEntries      int
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return nil, err
	}

	return &ResponseCachePolicy{
		cache:                newInMemoryCache(cfg.maxEntries, cfg.cleanupInterval),
		ttl:                  cfg.ttl,
		cacheableStatusCodes: cfg.cacheableStatusCodes,
	}, nil
}

func (p *ResponseCachePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

func (p *ResponseCachePolicy) OnRequestHeaders(
	ctx context.Context,
	reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{},
) policy.RequestHeaderAction {
	if reqCtx == nil {
		return policy.UpstreamRequestHeaderModifications{}
	}

	if reqCtx.SharedContext == nil {
		reqCtx.SharedContext = &policy.SharedContext{}
	}

	method := strings.ToUpper(strings.TrimSpace(reqCtx.Method))
	if method != "GET" && method != "HEAD" {
		return policy.UpstreamRequestHeaderModifications{}
	}

	cacheKey := buildCacheKey(reqCtx)
	if cacheKey == "" {
		return policy.UpstreamRequestHeaderModifications{}
	}

	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]interface{})
	}
	reqCtx.Metadata[cacheKeyMetadataKey] = cacheKey

	entry, ok := p.cache.Get(cacheKey)
	if !ok {
		return policy.UpstreamRequestHeaderModifications{}
	}

	if method == "GET" && !entry.hasResponseBody {
		return policy.UpstreamRequestHeaderModifications{}
	}

	slog.Info("ResponseCache: Serving response from cache",
		"requestID", reqCtx.RequestID,
		"method", method,
		"path", reqCtx.Path,
		"cacheKey", cacheKey,
		"statusCode", entry.statusCode,
	)

	headers := cloneHeaders(entry.headers)
	headers[cacheHitHeader] = cacheHitValue

	body := []byte(nil)
	if method == "GET" && entry.hasResponseBody {
		body = append(body, entry.body...)
	}

	return policy.ImmediateResponse{
		StatusCode: entry.statusCode,
		Headers:    headers,
		Body:       body,
	}
}

func (p *ResponseCachePolicy) OnResponseBody(
	ctx context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if respCtx == nil {
		return policy.DownstreamResponseModifications{}
	}

	if respCtx.SharedContext == nil || respCtx.Metadata == nil {
		return policy.DownstreamResponseModifications{}
	}

	cacheKey, ok := respCtx.Metadata[cacheKeyMetadataKey].(string)
	if !ok || cacheKey == "" {
		return policy.DownstreamResponseModifications{}
	}

	if _, cacheable := p.cacheableStatusCodes[respCtx.ResponseStatus]; !cacheable {
		return policy.DownstreamResponseModifications{}
	}

	headers := extractCacheableHeaders(respCtx.ResponseHeaders)
	var body []byte
	if respCtx.ResponseBody != nil && len(respCtx.ResponseBody.Content) > 0 {
		body = append(body, respCtx.ResponseBody.Content...)
	}

	p.cache.Set(cacheKey, cachedResponse{
		statusCode:      respCtx.ResponseStatus,
		headers:         headers,
		body:            body,
		hasResponseBody: len(body) > 0,
	}, p.ttl)

	return policy.DownstreamResponseModifications{}
}

func parseConfig(params map[string]interface{}) (cacheConfig, error) {
	cfg := cacheConfig{
		ttl:             defaultTTL,
		maxEntries:      defaultMaxEntries,
		cleanupInterval: defaultCleanupInterval,
		cacheableStatusCodes: map[int]struct{}{
			200: {},
		},
	}

	if params == nil {
		return cfg, nil
	}

	if ttlRaw, ok := params["ttl"]; ok {
		ttlStr, ok := ttlRaw.(string)
		if !ok {
			return cfg, fmt.Errorf("'ttl' must be a string")
		}
		ttl, err := time.ParseDuration(ttlStr)
		if err != nil || ttl <= 0 {
			return cfg, fmt.Errorf("'ttl' must be a valid positive duration")
		}
		cfg.ttl = ttl
	}

	if statusCodesRaw, ok := params["cacheableStatusCodes"]; ok {
		statusCodes, ok := statusCodesRaw.([]interface{})
		if !ok || len(statusCodes) == 0 {
			return cfg, fmt.Errorf("'cacheableStatusCodes' must be a non-empty array")
		}
		cfg.cacheableStatusCodes = make(map[int]struct{}, len(statusCodes))
		for i, raw := range statusCodes {
			statusCode, err := toInt(raw)
			if err != nil || statusCode < 100 || statusCode > 599 {
				return cfg, fmt.Errorf("'cacheableStatusCodes[%d]' must be an integer between 100 and 599", i)
			}
			cfg.cacheableStatusCodes[statusCode] = struct{}{}
		}
	}

	memoryRaw, ok := params["memory"]
	if !ok {
		return cfg, nil
	}

	memoryParams, ok := memoryRaw.(map[string]interface{})
	if !ok {
		return cfg, fmt.Errorf("'memory' must be an object")
	}

	if maxEntriesRaw, ok := memoryParams["maxEntries"]; ok {
		maxEntries, err := toInt(maxEntriesRaw)
		if err != nil || maxEntries <= 0 {
			return cfg, fmt.Errorf("'memory.maxEntries' must be a positive integer")
		}
		cfg.maxEntries = maxEntries
	}

	if cleanupIntervalRaw, ok := memoryParams["cleanupInterval"]; ok {
		cleanupIntervalStr, ok := cleanupIntervalRaw.(string)
		if !ok {
			return cfg, fmt.Errorf("'memory.cleanupInterval' must be a string")
		}
		if cleanupIntervalStr == "0" {
			cfg.cleanupInterval = 0
		} else {
			cleanupInterval, err := time.ParseDuration(cleanupIntervalStr)
			if err != nil || cleanupInterval < 0 {
				return cfg, fmt.Errorf("'memory.cleanupInterval' must be a valid duration or 0")
			}
			cfg.cleanupInterval = cleanupInterval
		}
	}

	return cfg, nil
}

func buildCacheKey(reqCtx *policy.RequestHeaderContext) string {
	if reqCtx == nil {
		return ""
	}

	rawPath := strings.TrimSpace(reqCtx.Path)
	if rawPath == "" {
		return ""
	}

	pathPart := rawPath
	rawQuery := ""
	if idx := strings.Index(rawPath, "?"); idx >= 0 {
		pathPart = rawPath[:idx]
		rawQuery = rawPath[idx+1:]
	}

	normalizedQuery := normalizeQuery(rawQuery)
	var builder strings.Builder
	builder.WriteString(strings.TrimSpace(reqCtx.Vhost))
	builder.WriteString("|")
	builder.WriteString(strings.TrimSpace(reqCtx.APIContext))
	builder.WriteString("|")
	builder.WriteString(pathPart)
	if normalizedQuery != "" {
		builder.WriteString("?")
		builder.WriteString(normalizedQuery)
	}
	return builder.String()
}

func normalizeQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		vals := append([]string(nil), values[key]...)
		sort.Strings(vals)
		escapedKey := url.QueryEscape(key)
		if len(vals) == 0 {
			parts = append(parts, escapedKey+"=")
			continue
		}
		for _, value := range vals {
			parts = append(parts, escapedKey+"="+url.QueryEscape(value))
		}
	}

	return strings.Join(parts, "&")
}

func extractCacheableHeaders(headers *policy.Headers) map[string]string {
	if headers == nil {
		return map[string]string{}
	}

	result := make(map[string]string)
	headers.Iterate(func(key string, values []string) {
		if _, skip := hopByHopHeaders[strings.ToLower(key)]; skip || len(values) == 0 {
			return
		}
		result[key] = strings.Join(values, ", ")
	})
	return result
}

func cloneHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}
	return cloned
}

func toInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("not an integer")
		}
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, fmt.Errorf("unsupported type %T", value)
	}
}

func newInMemoryCache(maxEntries int, cleanupInterval time.Duration) *inMemoryCache {
	return &inMemoryCache{
		entries:         make(map[string]cacheEntry),
		maxEntries:      maxEntries,
		cleanupInterval: cleanupInterval,
		lastCleanup:     time.Now(),
	}
}

func (c *inMemoryCache) Get(key string) (cachedResponse, bool) {
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		c.cleanupIfNeeded(now)
		return cachedResponse{}, false
	}

	if now.After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		c.cleanupIfNeeded(now)
		return cachedResponse{}, false
	}

	c.mu.Lock()
	entry.lastAccess = now
	c.entries[key] = entry
	c.mu.Unlock()
	c.cleanupIfNeeded(now)

	return cloneResponse(entry.response), true
}

func (c *inMemoryCache) Set(key string, response cachedResponse, ttl time.Duration) {
	now := time.Now()

	c.mu.Lock()
	c.entries[key] = cacheEntry{
		response:   cloneResponse(response),
		expiresAt:  now.Add(ttl),
		lastAccess: now,
	}
	if len(c.entries) > c.maxEntries {
		c.evictOldestLocked()
	}
	c.mu.Unlock()

	c.cleanupIfNeeded(now)
}

func (c *inMemoryCache) cleanupIfNeeded(now time.Time) {
	if c.cleanupInterval == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if now.Sub(c.lastCleanup) < c.cleanupInterval {
		return
	}

	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
	c.lastCleanup = now
}

func (c *inMemoryCache) evictOldestLocked() {
	if len(c.entries) <= c.maxEntries {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, entry := range c.entries {
		if first || entry.lastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastAccess
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func cloneResponse(response cachedResponse) cachedResponse {
	cloned := cachedResponse{
		statusCode:      response.statusCode,
		headers:         cloneHeaders(response.headers),
		hasResponseBody: response.hasResponseBody,
	}
	if len(response.body) > 0 {
		cloned.body = append([]byte(nil), response.body...)
	}
	return cloned
}
