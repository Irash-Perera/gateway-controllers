package modelroundrobin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestModelRoundRobinPolicy_Mode(t *testing.T) {
	p := &ModelRoundRobinPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestModelRoundRobinPolicy_GetPolicy_ParseErrors(t *testing.T) {
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
			name: "model item not object",
			params: map[string]interface{}{
				"models": []interface{}{"a"},
			},
			wantErrContain: "'models[0]' must be an object",
		},
		{
			name: "model missing name",
			params: map[string]interface{}{
				"models": []interface{}{map[string]interface{}{}},
			},
			wantErrContain: "'models[0].model' is required",
		},
		{
			name: "model name wrong type",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": 1},
				},
			},
			wantErrContain: "'models[0].model' must be a string",
		},
		{
			name: "model name empty",
			params: map[string]interface{}{
				"models": []interface{}{
					map[string]interface{}{"model": ""},
				},
			},
			wantErrContain: "'models[0].model' must have a minimum length of 1",
		},
		{
			name: "suspendDuration invalid",
			params: map[string]interface{}{
				"models":          baseRRModels(),
				"suspendDuration": "30",
			},
			wantErrContain: "'suspendDuration' must be an integer",
		},
		{
			name: "suspendDuration negative",
			params: map[string]interface{}{
				"models":          baseRRModels(),
				"suspendDuration": -1,
			},
			wantErrContain: "'suspendDuration' must be >= 0",
		},
		{
			name: "requestModel missing",
			params: map[string]interface{}{
				"models": baseRRModels(),
			},
			wantErrContain: "'requestModel' configuration is required",
		},
		{
			name: "requestModel wrong type",
			params: map[string]interface{}{
				"models":       baseRRModels(),
				"requestModel": "x",
			},
			wantErrContain: "'requestModel' must be an object",
		},
		{
			name: "requestModel location missing",
			params: map[string]interface{}{
				"models":       baseRRModels(),
				"requestModel": map[string]interface{}{"identifier": "$.model"},
			},
			wantErrContain: "'requestModel.location' is required",
		},
		{
			name: "requestModel location invalid",
			params: map[string]interface{}{
				"models": baseRRModels(),
				"requestModel": map[string]interface{}{
					"location":   "cookie",
					"identifier": "$.model",
				},
			},
			wantErrContain: "'requestModel.location' must be one of: payload, header, queryParam, pathParam",
		},
		{
			name: "requestModel identifier missing",
			params: map[string]interface{}{
				"models": baseRRModels(),
				"requestModel": map[string]interface{}{
					"location": "payload",
				},
			},
			wantErrContain: "'requestModel.identifier' is required",
		},
		{
			name: "requestModel identifier wrong type",
			params: map[string]interface{}{
				"models": baseRRModels(),
				"requestModel": map[string]interface{}{
					"location":   "payload",
					"identifier": 1,
				},
			},
			wantErrContain: "'requestModel.identifier' must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestModelRoundRobinPolicy_GetPolicy_SuccessAndDefaults(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
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
}

func TestModelRoundRobinPolicy_OnRequestBody_PayloadRoundRobin(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	})

	// Phase 1: headers — selects model and stores in metadata
	shared1 := rrSharedContext()
	headerCtx1 := &policy.RequestHeaderContext{SharedContext: shared1}
	p.OnRequestHeaders(headerCtx1, nil)

	// Phase 2: body — substitutes selected model into payload
	bodyCtx1 := &policy.RequestContext{
		SharedContext: shared1,
		Body:          &policy.Body{Content: []byte(`{"model":"original","x":"y"}`), Present: true},
	}
	action1 := p.OnRequestBody(bodyCtx1, nil)
	mods1 := mustRRRequestMods(t, action1)
	got1 := decodeJSONMapRR(t, mods1.Body)
	if got1["model"] != "gpt-4" {
		t.Fatalf("expected first selected model gpt-4, got %v", got1["model"])
	}
	if shared1.Metadata[MetadataKeySelectedModel] != "gpt-4" {
		t.Fatalf("expected selected model metadata to be set")
	}

	shared2 := rrSharedContext()
	headerCtx2 := &policy.RequestHeaderContext{SharedContext: shared2}
	p.OnRequestHeaders(headerCtx2, nil)

	bodyCtx2 := &policy.RequestContext{
		SharedContext: shared2,
		Body:          &policy.Body{Content: []byte(`{"model":"original2"}`), Present: true},
	}
	action2 := p.OnRequestBody(bodyCtx2, nil)
	mods2 := mustRRRequestMods(t, action2)
	got2 := decodeJSONMapRR(t, mods2.Body)
	if got2["model"] != "gpt-35" {
		t.Fatalf("expected second selected model gpt-35, got %v", got2["model"])
	}
}

func TestModelRoundRobinPolicy_OnRequestHeaders_QueryParamAndPathParamMutation(t *testing.T) {
	pQuery := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "queryParam",
			"identifier": "model",
		},
	})
	queryCtx := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Path:          "/v1/chat?model=old&x=1",
	}
	queryAction := pQuery.OnRequestHeaders(queryCtx, nil)
	queryMods := mustRRRequestHeaderMods(t, queryAction)
	if got := queryMods.HeadersToSet[":path"]; !strings.Contains(got, "model=gpt-4") {
		t.Fatalf("expected query path to include new model, got %q", got)
	}

	pPath := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "pathParam",
			"identifier": `/models/([^/]+)`,
		},
	})
	pathCtx := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Path:          "/v1/models/old/completions?x=1",
	}
	pathAction := pPath.OnRequestHeaders(pathCtx, nil)
	pathMods := mustRRRequestHeaderMods(t, pathAction)
	if got := pathMods.HeadersToSet[":path"]; !strings.Contains(got, "/models/gpt-4/") {
		t.Fatalf("expected path to include new model, got %q", got)
	}
}

func TestModelRoundRobinPolicy_OnRequestHeaders_AllModelsSuspended(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models": baseRRModels(),
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	until := time.Now().Add(10 * time.Minute)
	p.suspendedModels["gpt-4"] = until
	p.suspendedModels["gpt-35"] = until

	ctx := &policy.RequestHeaderContext{
		SharedContext: rrSharedContext(),
		Headers:       policy.NewHeaders(map[string][]string{"x-model": {"orig"}}),
	}
	action := p.OnRequestHeaders(ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when all models suspended, got %T", action)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("unexpected status code: got %d, want 503", resp.StatusCode)
	}
}

func TestModelRoundRobinPolicy_OnResponseHeaders_SuspendsModelOnError(t *testing.T) {
	p := mustGetRRPolicy(t, map[string]interface{}{
		"models":          baseRRModels(),
		"suspendDuration": 60,
		"requestModel": map[string]interface{}{
			"location":   "header",
			"identifier": "x-model",
		},
	})

	sharedCtx := &policy.SharedContext{
		RequestID: "test-id",
		Metadata: map[string]interface{}{
			MetadataKeySelectedModel: "gpt-4",
		},
	}
	ctx := &policy.ResponseHeaderContext{
		SharedContext:  sharedCtx,
		ResponseStatus: 500,
	}

	action := p.OnResponseHeaders(ctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	until, exists := p.suspendedModels["gpt-4"]
	if !exists {
		t.Fatalf("expected model to be suspended")
	}
	if !until.After(time.Now()) {
		t.Fatalf("expected suspension expiry in future")
	}
}

func TestModelRoundRobinPolicy_SelectNextAvailableModel_SkipsAndRecoversSuspended(t *testing.T) {
	p := &ModelRoundRobinPolicy{
		currentIndex:    0,
		suspendedModels: map[string]time.Time{"a": time.Now().Add(5 * time.Minute)},
	}
	models := []ModelConfig{{Model: "a"}, {Model: "b"}}

	got := p.selectNextAvailableModel(models)
	if got == nil || got.Model != "b" {
		t.Fatalf("expected to skip suspended a and pick b, got %+v", got)
	}

	p.suspendedModels["a"] = time.Now().Add(-1 * time.Minute)
	got2 := p.selectNextAvailableModel(models)
	if got2 == nil || got2.Model != "a" {
		t.Fatalf("expected expired suspension model a to be selected, got %+v", got2)
	}
}

func TestModelRoundRobinPolicy_ExtractInt(t *testing.T) {
	if v, err := extractInt(3); err != nil || v != 3 {
		t.Fatalf("expected int extraction to work, got v=%d err=%v", v, err)
	}
	if v, err := extractInt(float64(4)); err != nil || v != 4 {
		t.Fatalf("expected float integer extraction to work, got v=%d err=%v", v, err)
	}
	if _, err := extractInt(float64(4.2)); err == nil {
		t.Fatalf("expected error for non-integer float")
	}
}

func mustGetRRPolicy(t *testing.T, params map[string]interface{}) *ModelRoundRobinPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	rp, ok := p.(*ModelRoundRobinPolicy)
	if !ok {
		t.Fatalf("expected *ModelRoundRobinPolicy, got %T", p)
	}
	return rp
}

func mustRRRequestHeaderMods(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	return mods
}

func mustRRRequestMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func decodeJSONMapRR(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("failed to unmarshal json body: %v", err)
	}
	return m
}

func rrSharedContext() *policy.SharedContext {
	return &policy.SharedContext{
		RequestID: "req-id",
		Metadata:  map[string]interface{}{},
	}
}

func baseRRModels() []interface{} {
	return []interface{}{
		map[string]interface{}{"model": "gpt-4"},
		map[string]interface{}{"model": "gpt-35"},
	}
}
