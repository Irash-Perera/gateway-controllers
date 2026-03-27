/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package tokenbasedratelimit

import (
	"sync"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// TestTokenBasedRateLimitPolicy_Mode tests the processing mode
func TestTokenBasedRateLimitPolicy_Mode(t *testing.T) {
	p := &TokenBasedRateLimitPolicy{}
	mode := p.Mode()

	expected := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeBuffer, // Need body for token extraction
	}

	if mode != expected {
		t.Errorf("Expected mode %+v, got %+v", expected, mode)
	}
}

// TestTokenBasedRateLimitPolicy_GetPolicy tests policy creation
func TestTokenBasedRateLimitPolicy_GetPolicy(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(100),
				"duration": "1m",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if p == nil {
		t.Fatal("Expected policy instance, got nil")
	}

	tbPolicy, ok := p.(*TokenBasedRateLimitPolicy)
	if !ok {
		t.Fatalf("Expected TokenBasedRateLimitPolicy, got %T", p)
	}

	if tbPolicy.metadata.RouteName != "test-route" {
		t.Errorf("Expected route name 'test-route', got '%s'", tbPolicy.metadata.RouteName)
	}
}

// TestTokenBasedRateLimitPolicy_DelegateRaceCondition specifically tests the race condition fix
func TestTokenBasedRateLimitPolicy_DelegateRaceCondition(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "race-test-route",
	}

	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(100),
				"duration": "1m",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	tbPolicy := p.(*TokenBasedRateLimitPolicy)

	var wg sync.WaitGroup
	numGoroutines := 50
	providerName := "race-test-provider"

	// Launch many goroutines trying to resolve the same delegate
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This will fail due to missing store, but tests the race condition fix
			_, _ = tbPolicy.resolveDelegate(providerName, params)
		}()
	}

	wg.Wait()

	// Verify only one delegate attempt was stored (even though all failed)
	// The test passes if no race detector warnings are triggered
	t.Log("Race condition test completed without panics")
}

// TestTokenBasedRateLimitPolicy_ConcurrentAccess tests thread-safe delegate creation
func TestTokenBasedRateLimitPolicy_ConcurrentAccess(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(10),
				"duration": "1m",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	tbPolicy := p.(*TokenBasedRateLimitPolicy)

	var wg sync.WaitGroup
	numGoroutines := 100
	var successCount atomic.Int32

	// Concurrent access without proper mock store - this will test the race condition handling
	// In this case, resolveDelegate will fail, but we verify no panic/race occurs
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tbPolicy.resolveDelegate("test-provider", params)
			// resolveDelegate may return error due to missing store, but shouldn't panic
			if err != nil {
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// All goroutines should complete without panic
	t.Logf("Completed %d concurrent requests, %d returned error (expected due to missing store)", numGoroutines, successCount.Load())
}

// TestTransformToRatelimitParams tests the parameter transformation
func TestTransformToRatelimitParams(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(100),
				"duration": "1m",
			},
		},
		"completionTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(200),
				"duration": "1m",
			},
		},
		"totalTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(300),
				"duration": "1m",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"identifier": "$.usage.prompt_tokens",
			},
			"completionTokens": map[string]interface{}{
				"identifier": "$.usage.completion_tokens",
			},
			"totalTokens": map[string]interface{}{
				"identifier": "$.usage.total_tokens",
			},
		},
	}

	result := transformToRatelimitParams(params, template)

	// Check quotas were created
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 3 {
		t.Errorf("Expected 3 quotas, got %d", len(quotas))
	}

	// Check passthrough parameters
	if result["algorithm"] != "fixed-window" {
		t.Errorf("Expected algorithm 'fixed-window', got %v", result["algorithm"])
	}

	if result["backend"] != "memory" {
		t.Errorf("Expected backend 'memory', got %v", result["backend"])
	}
}

// TestConvertLimits tests the limit conversion function
func TestConvertLimits(t *testing.T) {
	rawLimits := []interface{}{
		map[string]interface{}{
			"count":    float64(100),
			"duration": "1m",
		},
		map[string]interface{}{
			"count":    float64(1000),
			"duration": "1h",
		},
	}

	converted := convertLimits(rawLimits)

	if len(converted) != 2 {
		t.Fatalf("Expected 2 converted limits, got %d", len(converted))
	}

	first := converted[0].(map[string]interface{})
	if first["limit"] != float64(100) {
		t.Errorf("Expected limit 100, got %v", first["limit"])
	}
	if first["duration"] != "1m" {
		t.Errorf("Expected duration '1m', got %v", first["duration"])
	}
}

// TestConvertLimits_InvalidInput tests handling of invalid input
func TestConvertLimits_InvalidInput(t *testing.T) {
	// Test with nil
	result := convertLimits(nil)
	if result != nil {
		t.Errorf("Expected nil for nil input, got %v", result)
	}

	// Test with non-array
	result = convertLimits("not-an-array")
	if result != nil {
		t.Errorf("Expected nil for non-array input, got %v", result)
	}

	// Test with invalid items
	rawLimits := []interface{}{
		"not-a-map",
		map[string]interface{}{
			"count":    float64(100),
			"duration": "1m",
		},
	}

	converted := convertLimits(rawLimits)
	// Should skip invalid items
	if len(converted) != 1 {
		t.Errorf("Expected 1 valid converted limit, got %d", len(converted))
	}
}

// TestTransformToRatelimitParams_NoLimits tests transformation with missing limits
func TestTransformToRatelimitParams_NoLimits(t *testing.T) {
	params := map[string]interface{}{
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	template := map[string]interface{}{}

	result := transformToRatelimitParams(params, template)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	// Should have 0 quotas since no limits are configured
	if len(quotas) != 0 {
		t.Errorf("Expected 0 quotas when no limits configured, got %d", len(quotas))
	}
}

// TestTransformToRatelimitParams_EmptyPromptAndCompletionLimits ensures empty arrays are ignored.
func TestTransformToRatelimitParams_EmptyPromptAndCompletionLimits(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits":     []interface{}{},
		"completionTokenLimits": []interface{}{},
		"totalTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(10),
				"duration": "1m",
			},
		},
	}

	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"identifier": "$.usage.prompt_tokens",
				"location":   "payload",
			},
			"completionTokens": map[string]interface{}{
				"identifier": "$.usage.completion_tokens",
				"location":   "payload",
			},
			"totalTokens": map[string]interface{}{
				"identifier": "$.usage.total_tokens",
				"location":   "payload",
			},
		},
	}

	result := transformToRatelimitParams(params, template)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 1 {
		t.Fatalf("Expected only 1 quota (total_tokens), got %d", len(quotas))
	}

	quota, ok := quotas[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected quota to be map[string]interface{}, got %T", quotas[0])
	}

	if quota["name"] != "total_tokens" {
		t.Fatalf("Expected quota name total_tokens, got %v", quota["name"])
	}
}

// TestTransformToRatelimitParams_NoTemplatePaths tests transformation without template paths
func TestTransformToRatelimitParams_NoTemplatePaths(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(100),
				"duration": "1m",
			},
		},
	}

	// Template without proper spec paths
	template := map[string]interface{}{}

	result := transformToRatelimitParams(params, template)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 1 {
		t.Fatalf("Expected 1 quota, got %d", len(quotas))
	}

	quota := quotas[0].(map[string]interface{})

	// Should have key extraction but no cost extraction
	if _, hasCostExtraction := quota["costExtraction"]; hasCostExtraction {
		t.Error("Expected no costExtraction when template paths are missing")
	}

	if _, hasKeyExtraction := quota["keyExtraction"]; !hasKeyExtraction {
		t.Error("Expected keyExtraction to be present")
	}
}

// TestTokenBasedRateLimitPolicy_TransformToRatelimitParams_TemplateLocationMapping tests
// that different template locations (payload, header, metadata) are mapped correctly.
func TestTokenBasedRateLimitPolicy_TransformToRatelimitParams_TemplateLocationMapping(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(10), "duration": "1m"},
		},
		"completionTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(10), "duration": "1m"},
		},
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(10), "duration": "1m"},
		},
	}
	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.prompt_tokens",
			},
			"completionTokens": map[string]interface{}{
				"location":   "header",
				"identifier": "x-completion-cost",
			},
			"totalTokens": map[string]interface{}{
				"location":   "metadata",
				"identifier": "usage.total_tokens",
			},
		},
	}

	result := transformToRatelimitParams(params, template)
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatalf("Expected quotas to be []interface{}, got %T", result["quotas"])
	}

	quotaByName := make(map[string]map[string]interface{})
	for _, q := range quotas {
		qm, ok := q.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected quota map, got %T", q)
		}
		name, _ := qm["name"].(string)
		quotaByName[name] = qm
	}

	getSource := func(quotaName string) map[string]interface{} {
		t.Helper()
		quota := quotaByName[quotaName]
		if quota == nil {
			t.Fatalf("Missing quota %q", quotaName)
		}
		ce, ok := quota["costExtraction"].(map[string]interface{})
		if !ok {
			t.Fatalf("Missing costExtraction for quota %q", quotaName)
		}
		sources, ok := ce["sources"].([]interface{})
		if !ok || len(sources) != 1 {
			t.Fatalf("Expected one source for quota %q, got %v", quotaName, ce["sources"])
		}
		source, ok := sources[0].(map[string]interface{})
		if !ok {
			t.Fatalf("Expected source map for quota %q, got %T", quotaName, sources[0])
		}
		return source
	}

	promptSource := getSource("prompt_tokens")
	if promptSource["type"] != "response_body" || promptSource["jsonPath"] != "$.usage.prompt_tokens" {
		t.Fatalf("Unexpected prompt source mapping: %v", promptSource)
	}

	completionSource := getSource("completion_tokens")
	if completionSource["type"] != "request_header" || completionSource["key"] != "x-completion-cost" {
		t.Fatalf("Unexpected completion source mapping: %v", completionSource)
	}

	totalSource := getSource("total_tokens")
	if totalSource["type"] != "metadata" || totalSource["key"] != "usage.total_tokens" {
		t.Fatalf("Unexpected total source mapping: %v", totalSource)
	}
}
