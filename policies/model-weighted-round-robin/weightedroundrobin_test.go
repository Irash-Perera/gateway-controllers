package modelweightedroundrobin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestModelWeightedRoundRobinPolicy_Mode(t *testing.T) {
	p := &ModelWeightedRoundRobinPolicy{}
	got := p.Mode()
	want := policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha2.BodyModeBuffer,
		ResponseHeaderMode: policyv1alpha2.HeaderModeProcess,
		ResponseBodyMode:   policyv1alpha2.BodyModeBuffer,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestModelWeightedRoundRobinPolicy_GetPolicy_ParseErrors(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name:           "missing models",
			params:         map[string]interface{}{},
			wantErrContain: "'models' parameter is required",
		},
		{
			name: "models wrong type",
			params: map[string]interface{}{
				"models": "not-array",
			},
			wantErrContain: "'models' must be an array",
		},
		{
			name: "models empty",
			params: map[string]interface{}{
				"models": []interface{}{},
			},
			wantErrContain: "'models' array must contain at least one model",
		},
		{
			name: "missing weight",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": "gpt-4"},
				},
			},
			wantErrContain: "'models[0].weight' is required",
		},
		{
			name: "weight not integer",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": "gpt-4", "weight": 1.5},
				},
			},
			wantErrContain: "'models[0].weight' must be an integer",
		},
		{
			name: "weight too low",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": "gpt-4", "weight": 0},
				},
			},
			wantErrContain: "'models[0].weight' must be >= 1",
		},
		{
			name: "suspendDuration invalid",
			params: map[string]interface{}{
				"models":          baseWeightedModels(),
				"suspendDuration": "10",
			},
			wantErrContain: "'suspendDuration' must be an integer",
		},
		{
			name: "requestModel missing",
			params: map[string]interface{}{
				"models": baseWeightedModels(),
			},
			wantErrContain: "'requestModel' configuration is required",
		},
		{
			name: "requestModel invalid location",
			params: map[string]interface{}{
				"models": baseWeightedModels(),
				"requestModel": map[string]interface{}{
					"location":   "cookie",
					"identifier": "$.model",
				},
			},
			wantErrContain: "'requestModel.location' must be one of: payload, header, queryParam, pathParam",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestModelWeightedRoundRobinPolicy_GetPolicy_SuccessAndSequence(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	if len(p.params.Models) != 2 {
		t.Fatalf("expected two models, got %d", len(p.params.Models))
	}
	if p.params.SuspendDuration != DefaultSuspendDuration {
		t.Fatalf("expected default suspendDuration=%d, got %d", DefaultSuspendDuration, p.params.SuspendDuration)
	}
	// weight 2 + 1 => sequence length 3
	if len(p.weightedSequence) != 3 {
		t.Fatalf("expected weighted sequence length 3, got %d", len(p.weightedSequence))
	}
}

func TestModelWeightedRoundRobinPolicy_BuildWeightedSequence(t *testing.T) {
	models := []*WeightedModel{
		{Model: "a", Weight: 2},
		{Model: "b", Weight: 1},
		{Model: "c", Weight: 0},
	}
	seq := buildWeightedSequence(models)
	if len(seq) != 3 {
		t.Fatalf("expected sequence length 3, got %d", len(seq))
	}
	if seq[0].Model != "a" || seq[1].Model != "a" || seq[2].Model != "b" {
		t.Fatalf("unexpected sequence order: %+v", []string{seq[0].Model, seq[1].Model, seq[2].Model})
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequestBody_PayloadWeightedSelection(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	// weight distribution: gpt-4, gpt-4, gpt-35, ...
	// Request 1
	shared1 := weightedSharedContext()
	headerCtx1 := &policyv1alpha2.RequestHeaderContext{SharedContext: shared1}
	p.OnRequestHeaders(headerCtx1, nil)

	bodyCtx1 := &policyv1alpha2.RequestContext{
		SharedContext: shared1,
		Body:          &policyv1alpha2.Body{Content: []byte(`{"model":"orig"}`), Present: true},
	}
	a1 := p.OnRequestBody(bodyCtx1, nil)
	m1 := mustWeightedRequestMods(t, a1)
	j1 := decodeJSONMapWeighted(t, m1.Body)
	if j1["model"] != "gpt-4" {
		t.Fatalf("expected first model gpt-4, got %v", j1["model"])
	}

	// Request 2
	shared2 := weightedSharedContext()
	headerCtx2 := &policyv1alpha2.RequestHeaderContext{SharedContext: shared2}
	p.OnRequestHeaders(headerCtx2, nil)

	bodyCtx2 := &policyv1alpha2.RequestContext{
		SharedContext: shared2,
		Body:          &policyv1alpha2.Body{Content: []byte(`{"model":"orig2"}`), Present: true},
	}
	a2 := p.OnRequestBody(bodyCtx2, nil)
	m2 := mustWeightedRequestMods(t, a2)
	j2 := decodeJSONMapWeighted(t, m2.Body)
	if j2["model"] != "gpt-4" {
		t.Fatalf("expected second model gpt-4, got %v", j2["model"])
	}

	// Request 3
	shared3 := weightedSharedContext()
	headerCtx3 := &policyv1alpha2.RequestHeaderContext{SharedContext: shared3}
	p.OnRequestHeaders(headerCtx3, nil)

	bodyCtx3 := &policyv1alpha2.RequestContext{
		SharedContext: shared3,
		Body:          &policyv1alpha2.Body{Content: []byte(`{"model":"orig3"}`), Present: true},
	}
	a3 := p.OnRequestBody(bodyCtx3, nil)
	m3 := mustWeightedRequestMods(t, a3)
	j3 := decodeJSONMapWeighted(t, m3.Body)
	if j3["model"] != "gpt-35" {
		t.Fatalf("expected third model gpt-35, got %v", j3["model"])
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequestHeaders_QueryAndPathMutation(t *testing.T) {
	pQuery := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "queryParam",
			"identifier": "model",
		},
	})
	queryCtx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: weightedSharedContext(),
		Path:          "/v1/chat?model=old",
	}
	queryAction := pQuery.OnRequestHeaders(queryCtx, nil)
	queryMods := mustWeightedRequestHeaderMods(t, queryAction)
	if got := queryMods.HeadersToSet[":path"]; !strings.Contains(got, "model=gpt-4") {
		t.Fatalf("expected query path to include new model, got %q", got)
	}

	pPath := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "pathParam",
			"identifier": `/models/([^/]+)`,
		},
	})
	pathCtx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: weightedSharedContext(),
		Path:          "/v1/models/old/completions",
	}
	pathAction := pPath.OnRequestHeaders(pathCtx, nil)
	pathMods := mustWeightedRequestHeaderMods(t, pathAction)
	if got := pathMods.HeadersToSet[":path"]; !strings.Contains(got, "/models/gpt-4/") {
		t.Fatalf("expected path to include new model, got %q", got)
	}
}

func TestModelWeightedRoundRobinPolicy_OnRequestHeaders_AllModelsSuspended(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models": baseWeightedModels(),
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	until := time.Now().Add(10 * time.Minute)
	p.suspendedModels["gpt-4"] = until
	p.suspendedModels["gpt-35"] = until

	ctx := &policyv1alpha2.RequestHeaderContext{
		SharedContext: weightedSharedContext(),
		Headers:       policyv1alpha2.NewHeaders(map[string][]string{"x-model": {"orig"}}),
	}
	action := p.OnRequestHeaders(ctx, nil)
	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when all models suspended, got %T", action)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestModelWeightedRoundRobinPolicy_OnResponseHeaders_SuspendsSelectedModel(t *testing.T) {
	p := mustGetWeightedPolicy(t, map[string]interface{}{
		"models":          baseWeightedModels(),
		"suspendDuration": 30,
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	sharedCtx := &policyv1alpha2.SharedContext{
		RequestID: "id",
		Metadata: map[string]interface{}{
			MetadataKeySelectedModel: "gpt-4",
		},
	}
	ctx := &policyv1alpha2.ResponseHeaderContext{
		SharedContext:  sharedCtx,
		ResponseStatus: 429,
	}
	action := p.OnResponseHeaders(ctx, nil)
	if _, ok := action.(policyv1alpha2.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	if until, exists := p.suspendedModels["gpt-4"]; !exists || !until.After(time.Now()) {
		t.Fatalf("expected selected model to be suspended")
	}
}

func TestModelWeightedRoundRobinPolicy_SelectNextAvailable_SkipsSuspended(t *testing.T) {
	p := &ModelWeightedRoundRobinPolicy{
		suspendedModels: map[string]time.Time{
			"a": time.Now().Add(5 * time.Minute),
		},
		weightedSequence: []*WeightedModel{
			{Model: "a", Weight: 2},
			{Model: "b", Weight: 1},
		},
	}

	got := p.selectNextAvailableWeightedModel()
	if got == nil || got.Model != "b" {
		t.Fatalf("expected to skip suspended model a and pick b, got %+v", got)
	}
}

func mustGetWeightedPolicy(t *testing.T, params map[string]interface{}) *ModelWeightedRoundRobinPolicy {
	t.Helper()
	p, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	wp, ok := p.(*ModelWeightedRoundRobinPolicy)
	if !ok {
		t.Fatalf("expected *ModelWeightedRoundRobinPolicy, got %T", p)
	}
	return wp
}

func mustWeightedRequestHeaderMods(t *testing.T, action policyv1alpha2.RequestHeaderAction) policyv1alpha2.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policyv1alpha2.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	return mods
}

func mustWeightedRequestMods(t *testing.T, action policyv1alpha2.RequestAction) policyv1alpha2.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policyv1alpha2.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func decodeJSONMapWeighted(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("failed to unmarshal json body: %v", err)
	}
	return m
}

func weightedSharedContext() *policyv1alpha2.SharedContext {
	return &policyv1alpha2.SharedContext{
		RequestID: "req-id",
		Metadata:  map[string]interface{}{},
	}
}

func baseWeightedModels() []interface{} {
	return []interface{}{
		map[string]interface{}{"model": "gpt-4", "weight": 2},
		map[string]interface{}{"model": "gpt-35", "weight": 1},
	}
}
