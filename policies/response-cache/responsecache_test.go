package responsecache

import (
	"context"
	"reflect"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig(map[string]interface{}{
		"ttl":                  "90s",
		"cacheableStatusCodes": []interface{}{200, 204},
		"memory": map[string]interface{}{
			"maxEntries":      50,
			"cleanupInterval": "30s",
		},
	})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}

	if cfg.ttl != 90*time.Second {
		t.Fatalf("unexpected ttl: %v", cfg.ttl)
	}
	if cfg.maxEntries != 50 {
		t.Fatalf("unexpected maxEntries: %d", cfg.maxEntries)
	}
	if cfg.cleanupInterval != 30*time.Second {
		t.Fatalf("unexpected cleanupInterval: %v", cfg.cleanupInterval)
	}
	if _, ok := cfg.cacheableStatusCodes[204]; !ok {
		t.Fatalf("expected status code 204 to be cacheable")
	}
}

func TestBuildCacheKeyNormalizesQueryParams(t *testing.T) {
	key := buildCacheKey(&policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/books",
		},
		Vhost: "gw.example.com",
		Path:  "/items/42?b=2&a=3&a=1",
	})

	want := "gw.example.com|/books|/items/42?a=1&a=3&b=2"
	if key != want {
		t.Fatalf("unexpected cache key\nwant=%q\ngot=%q", want, key)
	}
}

func TestOnRequestHeadersSkipsNonCacheableMethods(t *testing.T) {
	p := &ResponseCachePolicy{cache: newInMemoryCache(10, 0), ttl: time.Minute}

	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
		},
		Method: "POST",
		Path:   "/items/42",
	}, nil)

	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected pass-through action, got %T", action)
	}
}

func TestOnRequestHeadersReturnsImmediateResponseOnGetHit(t *testing.T) {
	p := &ResponseCachePolicy{cache: newInMemoryCache(10, 0), ttl: time.Minute}
	p.cache.Set("gw.example.com|/books|/items/42?a=1", cachedResponse{
		statusCode:      200,
		headers:         map[string]string{"Content-Type": "application/json"},
		body:            []byte(`{"id":42}`),
		hasResponseBody: true,
	}, time.Minute)

	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/books",
			Metadata:   map[string]interface{}{},
		},
		Method: "GET",
		Path:   "/items/42?a=1",
		Vhost:  "gw.example.com",
	}, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if string(resp.Body) != `{"id":42}` {
		t.Fatalf("unexpected response body: %s", string(resp.Body))
	}
	if resp.Headers[cacheHitHeader] != cacheHitValue {
		t.Fatalf("expected cache hit header, got headers=%v", resp.Headers)
	}
}

func TestOnRequestHeadersReturnsHeaderOnlyOnHeadHit(t *testing.T) {
	p := &ResponseCachePolicy{cache: newInMemoryCache(10, 0), ttl: time.Minute}
	p.cache.Set("gw.example.com|/books|/items/42", cachedResponse{
		statusCode:      200,
		headers:         map[string]string{"ETag": "abc"},
		body:            []byte(`{"id":42}`),
		hasResponseBody: true,
	}, time.Minute)

	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/books",
			Metadata:   map[string]interface{}{},
		},
		Method: "HEAD",
		Path:   "/items/42",
		Vhost:  "gw.example.com",
	}, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if len(resp.Body) != 0 {
		t.Fatalf("expected empty body for HEAD, got %q", string(resp.Body))
	}
	if resp.Headers["ETag"] != "abc" {
		t.Fatalf("unexpected headers: %v", resp.Headers)
	}
}

func TestOnResponseBodyStoresResponseUsingRequestMetadata(t *testing.T) {
	p := &ResponseCachePolicy{
		cache: newInMemoryCache(10, 0),
		ttl:   time.Minute,
		cacheableStatusCodes: map[int]struct{}{
			200: {},
		},
	}

	action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{cacheKeyMetadataKey: "gw.example.com|/books|/items/42?a=1"},
		},
		ResponseStatus: 200,
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type":   {"application/json"},
			"content-length": {"99"},
			"etag":           {"abc"},
		}),
		ResponseBody: &policy.Body{
			Content: []byte(`{"id":42}`),
			Present: true,
		},
	}, nil)

	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response pass-through, got %T", action)
	}

	entry, ok := p.cache.Get("gw.example.com|/books|/items/42?a=1")
	if !ok {
		t.Fatal("expected cached entry")
	}
	if entry.statusCode != 200 {
		t.Fatalf("unexpected status code: %d", entry.statusCode)
	}
	if string(entry.body) != `{"id":42}` {
		t.Fatalf("unexpected cached body: %s", string(entry.body))
	}
	if _, found := entry.headers["content-length"]; found {
		t.Fatalf("content-length should not be cached: %v", entry.headers)
	}
}

func TestOnResponseBodySkipsNonCacheableStatus(t *testing.T) {
	p := &ResponseCachePolicy{
		cache: newInMemoryCache(10, 0),
		ttl:   time.Minute,
		cacheableStatusCodes: map[int]struct{}{
			200: {},
		},
	}

	p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{cacheKeyMetadataKey: "gw.example.com|/books|/items/42"},
		},
		ResponseStatus: 500,
		ResponseBody:   &policy.Body{Content: []byte("boom"), Present: true},
	}, nil)

	if _, ok := p.cache.Get("gw.example.com|/books|/items/42"); ok {
		t.Fatal("did not expect 500 response to be cached")
	}
}

func TestExtractCacheableHeaders(t *testing.T) {
	headers := extractCacheableHeaders(policy.NewHeaders(map[string][]string{
		"content-type":      {"application/json"},
		"cache-control":     {"max-age=60"},
		"transfer-encoding": {"chunked"},
		"x-custom-response": {"one", "two"},
	}))

	want := map[string]string{
		"content-type":      "application/json",
		"cache-control":     "max-age=60",
		"x-custom-response": "one, two",
	}
	if !reflect.DeepEqual(headers, want) {
		t.Fatalf("unexpected headers\nwant=%v\ngot=%v", want, headers)
	}
}
