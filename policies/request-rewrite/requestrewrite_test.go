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

package requestrewrite

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func makeCtx(apiContext, operationPath, requestPath string, headers map[string][]string) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "req-test",
			Metadata:      map[string]interface{}{},
			APIContext:    apiContext,
			OperationPath: operationPath,
		},
		Path:    requestPath,
		Headers: policy.NewHeaders(headers),
	}
}

func assertPath(t *testing.T, result policy.RequestHeaderAction, want string) {
	t.Helper()
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}
	if mods.Path == nil {
		t.Fatalf("expected path %q, got nil", want)
	}
	if *mods.Path != want {
		t.Errorf("expected path %q, got %q", want, *mods.Path)
	}
}

func assertNoPathChange(t *testing.T, result policy.RequestHeaderAction) {
	t.Helper()
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}
	if mods.Path != nil {
		t.Errorf("expected no path change, got %q", *mods.Path)
	}
}

func assertMethod(t *testing.T, result policy.RequestHeaderAction, want string) {
	t.Helper()
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}
	if mods.Method == nil {
		t.Fatalf("expected method %q, got nil", want)
	}
	if *mods.Method != want {
		t.Errorf("expected method %q, got %q", want, *mods.Method)
	}
}

func assertImmediateResponse(t *testing.T, result policy.RequestHeaderAction, wantStatus int) {
	t.Helper()
	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != wantStatus {
		t.Errorf("expected status %d, got %d", wantStatus, resp.StatusCode)
	}
}

// ─── ReplaceFullPath ──────────────────────────────────────────────────────────

func TestReplaceFullPath_keepsAPIContextPrefix(t *testing.T) {
	// Regression test for the bug where ReplaceFullPath stripped the API context
	// prefix, preventing Envoy's route-level prefix rewrite from mapping the path
	// to the upstream base path (e.g. /anything).
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/req-transform-full/v1.0", "/api/v1", "/req-transform-full/v1.0/api/v1", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/fixed/path",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/req-transform-full/v1.0/fixed/path")
}

func TestReplaceFullPath_singleSegment(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/items", "/api/v1/items", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/new",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/new")
}

func TestReplaceFullPath_deepOperationPath(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/svc/v2", "/a/b/c", "/svc/v2/a/b/c", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/x/y",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/svc/v2/x/y")
}

func TestReplaceFullPath_withQueryParams(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/search", "/api/v1/search?q=foo&limit=10", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/find",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/find?limit=10&q=foo")
}

func TestReplaceFullPath_noChangeWhenSameRelativePath(t *testing.T) {
	p := &RequestRewritePolicy{}
	// replaceFullPath matches the current relative path — no effective change
	ctx := makeCtx("/api/v1", "/items", "/api/v1/items", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/items",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertNoPathChange(t, result)
}

// ─── ReplacePrefixMatch ───────────────────────────────────────────────────────

func TestReplacePrefixMatch_basic(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/pets", "/api/v1/pets", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":               "ReplacePrefixMatch",
			"replacePrefixMatch": "/animals",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/animals")
}

func TestReplacePrefixMatch_withSuffix(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/pets/*", "/api/v1/pets/123", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":               "ReplacePrefixMatch",
			"replacePrefixMatch": "/animals",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/animals/123")
}

func TestReplacePrefixMatch_operationPrefixNotInPath(t *testing.T) {
	// If the current path doesn't start with the operation path, no rewrite happens.
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/other", "/api/v1/pets", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":               "ReplacePrefixMatch",
			"replacePrefixMatch": "/animals",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertNoPathChange(t, result)
}

// ─── ReplaceRegexMatch ────────────────────────────────────────────────────────

func TestReplaceRegexMatch_basic(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/v1/users", "/api/v1/v1/users", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      "/v1/",
				"substitution": "/v2/",
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/v2/users")
}

func TestReplaceRegexMatch_withCaptureGroup(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/svc/v1", "/resource/123", "/svc/v1/resource/123", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      "/resource/(\\d+)",
				"substitution": "/items/\\1",
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/svc/v1/items/123")
}

func TestReplaceRegexMatch_reordersCapturedSegments(t *testing.T) {
	// Scenario: ReplaceRegexMatch reorders captured segments
	// Pattern:      ^/service/([^/]+)(/.*)$
	// Substitution: \2/instance/\1
	// Input path (relative): /service/foo/v1/api
	// Expected:              /v1/api/instance/foo
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/req-transform-regex-capture/v1.0", "/*", "/req-transform-regex-capture/v1.0/service/foo/v1/api", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      `^/service/([^/]+)(/.*)$`,
				"substitution": `\2/instance/\1`,
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/req-transform-regex-capture/v1.0/v1/api/instance/foo")
}

func TestReplaceRegexMatch_caseInsensitive(t *testing.T) {
	// Scenario: ReplaceRegexMatch is case-insensitive ((?i) flag in pattern)
	// Input path (relative): /aaa/XxX/bbb
	// Pattern:               (?i)/xxx/
	// Expected:              /aaa/yyy/bbb
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/req-transform-regex-ci/v1.0", "/*", "/req-transform-regex-ci/v1.0/aaa/XxX/bbb", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      "(?i)/xxx/",
				"substitution": "/yyy/",
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/req-transform-regex-ci/v1.0/aaa/yyy/bbb")
}

func TestReplaceRegexMatch_replacesAllMatches(t *testing.T) {
	// Scenario: ReplaceRegexMatch replaces all occurrences (not just first)
	// Input path (relative): /xxx/one/yyy/one/zzz
	// Pattern:               one
	// Expected:              /xxx/two/yyy/two/zzz
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/req-transform-regex-multi/v1.0", "/*", "/req-transform-regex-multi/v1.0/xxx/one/yyy/one/zzz", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      "one",
				"substitution": "two",
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/req-transform-regex-multi/v1.0/xxx/two/yyy/two/zzz")
}

func TestReplaceRegexMatch_invalidPattern(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/foo", "/api/v1/foo", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      "[invalid",
				"substitution": "/bar",
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	// Invalid regex — path is unchanged
	assertNoPathChange(t, result)
}

// ─── Method rewrite ───────────────────────────────────────────────────────────

func TestMethodRewrite_postToGet(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", nil)
	ctx.Method = "POST"
	params := map[string]interface{}{
		"methodRewrite": "GET",
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertMethod(t, result, "GET")
}

func TestMethodRewrite_caseInsensitiveInput(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", nil)
	params := map[string]interface{}{
		"methodRewrite": "post",
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertMethod(t, result, "POST")
}

func TestMethodRewrite_unsupportedMethod(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", nil)
	params := map[string]interface{}{
		"methodRewrite": "CONNECT",
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertImmediateResponse(t, result, 500)
}

func TestMethodRewrite_withPathRewrite(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/old", "/api/v1/old", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/new",
		},
		"methodRewrite": "POST",
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/new")
	assertMethod(t, result, "POST")
}

// ─── Query rewrite ────────────────────────────────────────────────────────────

func TestQueryRewrite_replace(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/search", "/api/v1/search?env=prod", nil)
	params := map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"action": "Replace",
					"name":   "env",
					"value":  "staging",
				},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/search?env=staging")
}

func TestQueryRewrite_remove(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/search", "/api/v1/search?q=foo&debug=true", nil)
	params := map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"action": "Remove",
					"name":   "debug",
				},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/search?q=foo")
}

func TestQueryRewrite_add(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/items", "/api/v1/items?sort=asc", nil)
	params := map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"action": "Add",
					"name":   "page",
					"value":  "1",
				},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/items?page=1&sort=asc")
}

func TestQueryRewrite_append(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/search", "/api/v1/search?tags=go", nil)
	params := map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"action":    "Append",
					"name":      "tags",
					"value":     "test",
					"separator": ",",
				},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/search?tags=go%2Ctest")
}

func TestQueryRewrite_replaceRegexMatch(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/list", "/api/v1/list?version=v1.2.3", nil)
	params := map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"action":       "ReplaceRegexMatch",
					"name":         "version",
					"pattern":      "v(\\d+)\\..*",
					"substitution": "v\\1",
				},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/list?version=v1")
}

func TestQueryRewrite_invalidQueryRegex(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/list", "/api/v1/list?v=foo", nil)
	params := map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"action":       "ReplaceRegexMatch",
					"name":         "v",
					"pattern":      "[bad",
					"substitution": "x",
				},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertImmediateResponse(t, result, 500)
}

func TestQueryRewrite_addReplaceRemoveCombined(t *testing.T) {
	// Scenario: Query rewrite adds, replaces, and removes parameters in one pass
	// Input:  ?q=old-value&debug=true
	// Rules:  Add source=legacy, Replace q=new-value, Remove debug
	// Output: ?q=new-value&source=legacy  (debug absent)
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/search", "/api/v1/search?q=old-value&debug=true", nil)
	params := map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Add", "name": "source", "value": "legacy"},
				map[string]interface{}{"action": "Replace", "name": "q", "value": "new-value"},
				map[string]interface{}{"action": "Remove", "name": "debug"},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/search?q=new-value&source=legacy")
}

func TestQueryRewrite_pathAndQueryTogether(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/old", "/api/v1/old?key=abc", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/new",
		},
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"action": "Remove",
					"name":   "key",
				},
			},
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/new")
}

// ─── Match conditions ─────────────────────────────────────────────────────────

func TestMatch_headerExact_matches(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", map[string][]string{
		"x-env": {"staging"},
	})
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-env", "type": "Exact", "value": "staging"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/new",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/new")
}

func TestMatch_headerExact_noMatch(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", map[string][]string{
		"x-env": {"prod"},
	})
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-env", "type": "Exact", "value": "staging"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/new",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertNoPathChange(t, result)
}

func TestMatch_headerRegex_matches(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", map[string][]string{
		"x-version": {"v2.5.1"},
	})
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-version", "type": "Regex", "value": "v2\\..*"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/v2",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/v2")
}

func TestMatch_headerPresent_matches(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", map[string][]string{
		"x-debug": {"1"},
	})
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-debug", "type": "Present"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/debug",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/debug")
}

func TestMatch_headerPresent_absent(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", nil)
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-debug", "type": "Present"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/debug",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertNoPathChange(t, result)
}

func TestMatch_queryParam_exact_matches(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data?mode=fast", nil)
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"queryParams": []interface{}{
				map[string]interface{}{"name": "mode", "type": "Exact", "value": "fast"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/fast-data",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/api/v1/fast-data?mode=fast")
}

func TestMatch_queryParam_exact_noMatch(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data?mode=slow", nil)
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"queryParams": []interface{}{
				map[string]interface{}{"name": "mode", "type": "Exact", "value": "fast"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/fast-data",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertNoPathChange(t, result)
}

func TestMatch_multipleHeaders_allMustMatch(t *testing.T) {
	p := &RequestRewritePolicy{}
	// Only one of two headers is present — rewrite should NOT apply.
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", map[string][]string{
		"x-a": {"1"},
	})
	params := map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-a", "type": "Present"},
				map[string]interface{}{"name": "x-b", "type": "Present"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/matched",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertNoPathChange(t, result)
}

// ─── API-level policy ─────────────────────────────────────────────────────────

func TestAPILevelPolicy_rewritesPrefixMatch(t *testing.T) {
	// Scenario: API-level policy rewrites the path prefix (no operationPath wildcard)
	// The policy is attached at the API level, not a specific operation.
	// APIContext acts as the base; OperationPath is the matched operation.
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/req-transform-api-prefix/v1.0", "/api/v1", "/req-transform-api-prefix/v1.0/api/v1", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":               "ReplacePrefixMatch",
			"replacePrefixMatch": "/api/v2",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/req-transform-api-prefix/v1.0/api/v2")
}

func TestAPILevelPolicy_rewritesMethod(t *testing.T) {
	// Scenario: API-level policy rewrites the HTTP method for all matching operations
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/req-transform-api-method/v1.0", "/test/*", "/req-transform-api-method/v1.0/test/hello", nil)
	ctx.Method = "GET"
	params := map[string]interface{}{
		"methodRewrite": "POST",
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertMethod(t, result, "POST")
}

// ─── Pass-through cases ───────────────────────────────────────────────────────

func TestPassThrough_nilParams(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", nil)
	result := p.OnRequestHeaders(context.Background(), ctx, nil)
	assertNoPathChange(t, result)
}

func TestPassThrough_emptyParams(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := makeCtx("/api/v1", "/data", "/api/v1/data", nil)
	result := p.OnRequestHeaders(context.Background(), ctx, map[string]interface{}{})
	assertNoPathChange(t, result)
}

func TestPassThrough_noAPIContext(t *testing.T) {
	// When the API context is not set, splitBasePath returns empty base and
	// the full path as relative, so joinBaseAndRelative returns the replacement
	// path without any prefix.
	p := &RequestRewritePolicy{}
	ctx := makeCtx("", "", "/api/v1/data", nil)
	params := map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/new",
		},
	}
	result := p.OnRequestHeaders(context.Background(), ctx, params)
	assertPath(t, result, "/new")
}

// ─── Unit tests for helper functions ─────────────────────────────────────────

func TestSplitBasePath(t *testing.T) {
	cases := []struct {
		name         string
		apiContext   string
		path         string
		wantBase     string
		wantRelative string
	}{
		{
			name:       "normal split",
			apiContext: "/api/v1", path: "/api/v1/pets",
			wantBase: "/api/v1", wantRelative: "/pets",
		},
		{
			name:       "trailing slash on context",
			apiContext: "/api/v1/", path: "/api/v1/pets",
			wantBase: "/api/v1", wantRelative: "/pets",
		},
		{
			name:       "empty context",
			apiContext: "", path: "/pets",
			wantBase: "", wantRelative: "/pets",
		},
		{
			name:       "path equals context",
			apiContext: "/api/v1", path: "/api/v1",
			wantBase: "/api/v1", wantRelative: "/",
		},
		{
			name:       "context not in path",
			apiContext: "/other", path: "/api/v1/pets",
			wantBase: "", wantRelative: "/api/v1/pets",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, rel := splitBasePath(tc.apiContext, tc.path)
			if base != tc.wantBase {
				t.Errorf("base: want %q, got %q", tc.wantBase, base)
			}
			if rel != tc.wantRelative {
				t.Errorf("relative: want %q, got %q", tc.wantRelative, rel)
			}
		})
	}
}

func TestJoinBaseAndRelative(t *testing.T) {
	cases := []struct {
		base, relative, want string
	}{
		{"/api/v1", "/pets", "/api/v1/pets"},
		{"/api/v1", "/", "/api/v1"},
		{"", "/pets", "/pets"},
		{"/api/v1", "", "/api/v1"},
		{"/api/v1", "pets", "/api/v1/pets"},
	}
	for _, tc := range cases {
		got := joinBaseAndRelative(tc.base, tc.relative)
		if got != tc.want {
			t.Errorf("joinBaseAndRelative(%q, %q) = %q, want %q", tc.base, tc.relative, got, tc.want)
		}
	}
}

func TestApplyPathRewrite_replacePrefix(t *testing.T) {
	cfg := &pathRewrite{Type: "ReplacePrefixMatch", ReplacePrefixMatch: "/new"}
	got := applyPathRewrite("/old", "/old/suffix", cfg)
	if got != "/new/suffix" {
		t.Errorf("want /new/suffix, got %q", got)
	}
}

func TestApplyPathRewrite_replacePrefix_wildcardOp(t *testing.T) {
	cfg := &pathRewrite{Type: "ReplacePrefixMatch", ReplacePrefixMatch: "/animals"}
	got := applyPathRewrite("/pets/*", "/pets/123", cfg)
	if got != "/animals/123" {
		t.Errorf("want /animals/123, got %q", got)
	}
}

func TestApplyPathRewrite_replaceFull(t *testing.T) {
	cfg := &pathRewrite{Type: "ReplaceFullPath", ReplaceFullPath: "/fixed"}
	got := applyPathRewrite("/any", "/any/path", cfg)
	if got != "/fixed" {
		t.Errorf("want /fixed, got %q", got)
	}
}

func TestApplyPathRewrite_replaceFull_emptyValue(t *testing.T) {
	cfg := &pathRewrite{Type: "ReplaceFullPath", ReplaceFullPath: ""}
	got := applyPathRewrite("/op", "/op/current", cfg)
	if got != "/op/current" {
		t.Errorf("want unchanged /op/current, got %q", got)
	}
}

func TestApplyPathRewrite_replaceRegex(t *testing.T) {
	cfg := &pathRewrite{
		Type: "ReplaceRegexMatch",
		ReplaceRegexMatch: &regexReplacement{
			Pattern:      "/v1/",
			Substitution: "/v2/",
		},
	}
	got := applyPathRewrite("", "/v1/users", cfg)
	if got != "/v2/users" {
		t.Errorf("want /v2/users, got %q", got)
	}
}

func TestApplyPathRewrite_unsupportedType(t *testing.T) {
	cfg := &pathRewrite{Type: "Unknown"}
	got := applyPathRewrite("", "/current", cfg)
	if got != "/current" {
		t.Errorf("want unchanged /current, got %q", got)
	}
}

func TestNormalizeRegexSubstitution(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"/v2/", "/v2/"},
		{"\\1-suffix", "$1-suffix"},
		{"prefix-\\2", "prefix-$2"},
		{"\\1/\\2", "$1/$2"},
	}
	for _, tc := range cases {
		got := normalizeRegexSubstitution(tc.in)
		if got != tc.want {
			t.Errorf("normalizeRegexSubstitution(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── GetPolicy ────────────────────────────────────────────────────────────────

func TestGetPolicy(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
	if _, ok := p.(*RequestRewritePolicy); !ok {
		t.Errorf("expected *RequestRewritePolicy, got %T", p)
	}
}

func TestMode(t *testing.T) {
	p := &RequestRewritePolicy{}
	m := p.Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("expected RequestHeaderMode=Process, got %v", m.RequestHeaderMode)
	}
	if m.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("expected RequestBodyMode=Skip, got %v", m.RequestBodyMode)
	}
}
