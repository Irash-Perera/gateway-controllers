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

package llmcostratelimit

import (
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// TestLLMCostRateLimitPolicy_Mode tests the processing mode
func TestLLMCostRateLimitPolicy_Mode(t *testing.T) {
	p := &LLMCostRateLimitPolicy{}
	mode := p.Mode()

	expected := policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha2.BodyModeSkip,
		ResponseHeaderMode: policyv1alpha2.HeaderModeProcess,
		ResponseBodyMode:   policyv1alpha2.BodyModeSkip,
	}

	if mode != expected {
		t.Errorf("Expected mode %+v, got %+v", expected, mode)
	}
}

// TestLLMCostRateLimitPolicy_GetPolicyV2 tests policy creation
func TestLLMCostRateLimitPolicy_GetPolicyV2(t *testing.T) {
	metadata := policyv1alpha2.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"promptTokenCost":     float64(0.000002),
		"completionTokenCost": float64(0.000006),
		"algorithm":           "fixed-window",
		"backend":             "memory",
	}

	p, err := GetPolicyV2(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if p == nil {
		t.Fatal("Expected policy instance, got nil")
	}

	costPolicy, ok := p.(*LLMCostRateLimitPolicy)
	if !ok {
		t.Fatalf("Expected LLMCostRateLimitPolicy, got %T", p)
	}

	if costPolicy.metadata.RouteName != "test-route" {
		t.Errorf("Expected route name 'test-route', got '%s'", costPolicy.metadata.RouteName)
	}
}

// TestTransformToRatelimitParams tests the parameter transformation
func TestTransformToRatelimitParams(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
			map[string]interface{}{
				"amount":   float64(100),
				"duration": "24h",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	result := transformToRatelimitParams(params)

	// Check quotas were created
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 1 {
		t.Fatalf("Expected 1 quota, got %d", len(quotas))
	}

	quota := quotas[0].(map[string]interface{})

	// Check limits were converted
	limits, ok := quota["limits"].([]interface{})
	if !ok {
		t.Fatal("Expected limits to be []interface{}")
	}

	if len(limits) != 2 {
		t.Errorf("Expected 2 limits, got %d", len(limits))
	}

	// Check cost extraction reads from x-llm-cost in SharedContext.Metadata
	costExtraction, ok := quota["costExtraction"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected costExtraction to be present")
	}

	sources, ok := costExtraction["sources"].([]interface{})
	if !ok || len(sources) != 1 {
		t.Fatalf("Expected 1 cost source (x-llm-cost metadata), got %d", len(sources))
	}

	source := sources[0].(map[string]interface{})
	if source["type"] != "response_metadata" {
		t.Errorf("Expected source type 'response_metadata', got %v", source["type"])
	}
	if source["key"] != "x-llm-cost" {
		t.Errorf("Expected source key 'x-llm-cost', got %v", source["key"])
	}

	// Check passthrough parameters
	if result["algorithm"] != "fixed-window" {
		t.Errorf("Expected algorithm 'fixed-window', got %v", result["algorithm"])
	}

	if result["backend"] != "memory" {
		t.Errorf("Expected backend 'memory', got %v", result["backend"])
	}
}

// TestTransformToRatelimitParams_CustomScaleFactor tests that a custom costScaleFactor is applied to the multiplier
func TestTransformToRatelimitParams_CustomScaleFactor(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"costScaleFactor": 1000000, // 1M micro-dollars
		"algorithm":       "fixed-window",
		"backend":         "memory",
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})
	costExtraction := quota["costExtraction"].(map[string]interface{})
	sources := costExtraction["sources"].([]interface{})
	source := sources[0].(map[string]interface{})

	if source["multiplier"] != float64(1000000) {
		t.Errorf("Expected multiplier 1000000, got %v", source["multiplier"])
	}
}

// TestTransformToRatelimitParams_NoBudgetLimits tests transformation with missing budgets
func TestTransformToRatelimitParams_NoBudgetLimits(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenCost": float64(0.000002),
		"algorithm":       "fixed-window",
		"backend":         "memory",
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	// Should have 0 quotas since no budget limits are configured
	if len(quotas) != 0 {
		t.Errorf("Expected 0 quotas when no budgets configured, got %d", len(quotas))
	}
}

// TestTransformToRatelimitParams_AlwaysHasCostExtraction tests that cost extraction
// is always configured regardless of other parameters, since it reads from SharedContext.Metadata.
func TestTransformToRatelimitParams_AlwaysHasCostExtraction(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})

	// x-llm-cost metadata source should always be present
	costExtraction, ok := quota["costExtraction"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected costExtraction to always be present")
	}

	sources, ok := costExtraction["sources"].([]interface{})
	if !ok || len(sources) != 1 {
		t.Fatalf("Expected 1 cost source, got %d", len(sources))
	}
}
