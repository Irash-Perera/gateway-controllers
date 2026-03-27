/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package llmcost

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	// MetadataLLMCost is the SharedContext metadata key for the calculated LLM cost.
	// Value is a USD float formatted to 10 decimal places.
	MetadataLLMCost = "x-llm-cost"

	// MetadataLLMCostStatus indicates whether the cost was successfully calculated.
	// Value is either "calculated" or "not_calculated".
	// This disambiguates x-llm-cost: 0 (which could mean zero cost or a failed calculation).
	MetadataLLMCostStatus = "x-llm-cost-status"

	costStatusCalculated    = "calculated"
	costStatusNotCalculated = "not_calculated"
)

// LLMCostPolicy calculates the cost of an LLM API call from the response body
// and stores the result in SharedContext.Metadata under "x-llm-cost" (USD float).
type LLMCostPolicy struct {
	pricingMap map[string]ModelPricing
}

var (
	instance     *LLMCostPolicy
	instanceOnce sync.Once
	instanceErr  error
)

// GetPolicy is the v1alpha factory entry point (loaded by v1alpha kernels).
// The returned concrete type also satisfies policyv1alpha2 phase interfaces
// (StreamingResponsePolicy, RequestPolicy, ResponsePolicy), so v1alpha2 kernels
// can discover those capabilities via type assertions even when using this factory.
func GetPolicy(
	_ policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	instanceOnce.Do(func() {
		pricingFile, _ := params["pricing_file"].(string)
		if pricingFile == "" {
			instanceErr = fmt.Errorf("llm-cost: pricing_file system parameter is required but not set")
			return
		}
		pm, err := loadPricingFromFile(pricingFile)
		if err != nil {
			instanceErr = fmt.Errorf("llm-cost: failed to load pricing file %q: %w", pricingFile, err)
			return
		}
		slog.Info("llm-cost: pricing map loaded", "path", pricingFile, "entries", len(pm))
		instance = &LLMCostPolicy{pricingMap: pm}
	})
	return instance, instanceErr
}

// GetPolicyV2 is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicyV2(
	metadata policyv1alpha2.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha2.Policy, error) {
	return GetPolicy(policy.PolicyMetadata{
		RouteName:  metadata.RouteName,
		APIId:      metadata.APIId,
		APIName:    metadata.APIName,
		APIVersion: metadata.APIVersion,
		AttachedTo: policy.Level(metadata.AttachedTo),
	}, params)
}

// Mode declares the SDK processing requirements:
//   - RequestBodyMode=Buffer: buffer the request so ctx.RequestBody is available
//     in OnResponse (needed for Anthropic speed parameter).
//   - ResponseBodyMode=Buffer: buffer the full response body so we can parse
//     the usage object and model name.
func (p *LLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestBodyMode:  policy.BodyModeBuffer,
		ResponseBodyMode: policy.BodyModeBuffer,
	}
}

// OnRequest is a no-op — all work is done in OnResponse.
func (p *LLMCostPolicy) OnRequest(ctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	return policy.UpstreamRequestModifications{}
}

// OnResponse reads the LLM response, looks up model pricing, calculates cost,
// and stores the result in SharedContext.Metadata.
func (p *LLMCostPolicy) OnResponse(ctx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if ctx.ResponseBody == nil || !ctx.ResponseBody.Present || len(ctx.ResponseBody.Content) == 0 {
		slog.Warn("llm-cost: empty or missing response body, skipping cost calculation")
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	responseBody := ctx.ResponseBody.Content

	// Extract model name from response body.
	// OpenAI-compatible providers use $.model; Gemini uses $.modelVersion.
	var probe struct {
		Model        string `json:"model"`
		ModelVersion string `json:"modelVersion"`
	}
	if err := json.Unmarshal(responseBody, &probe); err != nil {
		slog.Warn("llm-cost: could not parse response body", "error", err)
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}
	modelName := probe.Model
	if modelName == "" {
		modelName = probe.ModelVersion
	}
	if modelName == "" {
		slog.Warn("llm-cost: no model name found in response body ($.model or $.modelVersion)")
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	// Look up pricing entry.
	pricing, found := lookupPricing(p.pricingMap, modelName)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0", "model", modelName)
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	// Select provider calculator.
	calc := selectCalculator(pricing.Provider)
	if calc == nil {
		slog.Warn("llm-cost: unsupported provider, skipping cost calculation", "provider", pricing.Provider, "model", modelName)
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	// Get buffered request body (may be nil for providers that don't need it).
	var requestBody []byte
	if ctx.RequestBody != nil && ctx.RequestBody.Present {
		requestBody = ctx.RequestBody.Content
	}

	// Normalize provider-specific usage fields into our common Usage struct.
	usage, err := calc.Normalize(responseBody, requestBody)
	if err != nil {
		slog.Warn("llm-cost: failed to normalize usage", "model", modelName, "error", err)
		return setCostMetadata(ctx, 0.0, costStatusNotCalculated)
	}

	// Calculate base cost using the provider-agnostic generic calculator.
	baseCost := genericCalculateCost(usage, pricing)

	// Apply provider-specific adjustments (geo/speed multipliers, router flat cost, etc.).
	finalCost := calc.Adjust(baseCost, usage, pricing)

	slog.Debug("llm-cost: calculated cost",
		"model", modelName,
		"provider", pricing.Provider,
		"prompt_tokens", usage.PromptTokens,
		"completion_tokens", usage.CompletionTokens,
		"cost_usd", finalCost,
	)

	return setCostMetadata(ctx, finalCost, costStatusCalculated)
}

// setCostMetadata writes x-llm-cost and x-llm-cost-status into SharedContext.Metadata
// so downstream policies can read the cost without it being exposed as a response header.
func setCostMetadata(ctx *policy.ResponseContext, costUSD float64, status string) policy.ResponseAction {
	if ctx.SharedContext == nil {
		slog.Warn("llm-cost: SharedContext is nil, cannot set cost metadata")
		return policy.UpstreamResponseModifications{}
	}
	if ctx.SharedContext.Metadata == nil {
		ctx.SharedContext.Metadata = make(map[string]interface{})
	}
	ctx.SharedContext.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", costUSD)
	ctx.SharedContext.Metadata[MetadataLLMCostStatus] = status
	return policy.UpstreamResponseModifications{
		AnalyticsMetadata: map[string]interface{}{
			MetadataLLMCost: costUSD,
		},
	}
}

// OnResponseBody reads the LLM response, looks up model pricing, calculates cost,
// and stores the result in SharedContext.Metadata.
func (p *LLMCostPolicy) OnResponseBody(ctx *policyv1alpha2.ResponseContext, _ map[string]interface{}) policyv1alpha2.ResponseAction {
	if ctx.ResponseBody == nil || !ctx.ResponseBody.Present || len(ctx.ResponseBody.Content) == 0 {
		slog.Warn("llm-cost: empty or missing response body, skipping cost calculation")
		return setCostMetadataV2(ctx, 0.0, costStatusNotCalculated)
	}

	responseBody := ctx.ResponseBody.Content

	// Extract model name from response body.
	// OpenAI-compatible providers use $.model; Gemini uses $.modelVersion.
	var probe struct {
		Model        string `json:"model"`
		ModelVersion string `json:"modelVersion"`
	}
	if err := json.Unmarshal(responseBody, &probe); err != nil {
		slog.Warn("llm-cost: could not parse response body", "error", err)
		return setCostMetadataV2(ctx, 0.0, costStatusNotCalculated)
	}
	modelName := probe.Model
	if modelName == "" {
		modelName = probe.ModelVersion
	}
	if modelName == "" {
		slog.Warn("llm-cost: no model name found in response body ($.model or $.modelVersion)")
		return setCostMetadataV2(ctx, 0.0, costStatusNotCalculated)
	}

	// Look up pricing entry.
	pricing, found := lookupPricing(p.pricingMap, modelName)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0", "model", modelName)
		return setCostMetadataV2(ctx, 0.0, costStatusNotCalculated)
	}

	// Select provider calculator.
	calc := selectCalculator(pricing.Provider)
	if calc == nil {
		slog.Warn("llm-cost: unsupported provider, skipping cost calculation", "provider", pricing.Provider, "model", modelName)
		return setCostMetadataV2(ctx, 0.0, costStatusNotCalculated)
	}

	// Get buffered request body (may be nil for providers that don't need it).
	var requestBody []byte
	if ctx.RequestBody != nil && ctx.RequestBody.Present {
		requestBody = ctx.RequestBody.Content
	}

	// Normalize provider-specific usage fields into our common Usage struct.
	usage, err := calc.Normalize(responseBody, requestBody)
	if err != nil {
		slog.Warn("llm-cost: failed to normalize usage", "model", modelName, "error", err)
		return setCostMetadataV2(ctx, 0.0, costStatusNotCalculated)
	}

	// Calculate base cost using the provider-agnostic generic calculator.
	baseCost := genericCalculateCost(usage, pricing)

	// Apply provider-specific adjustments (geo/speed multipliers, router flat cost, etc.).
	finalCost := calc.Adjust(baseCost, usage, pricing)

	slog.Debug("llm-cost: calculated cost",
		"model", modelName,
		"provider", pricing.Provider,
		"prompt_tokens", usage.PromptTokens,
		"completion_tokens", usage.CompletionTokens,
		"cost_usd", finalCost,
	)

	return setCostMetadataV2(ctx, finalCost, costStatusCalculated)
}

// setCostMetadataV2 writes x-llm-cost and x-llm-cost-status into SharedContext.Metadata
// for the v1alpha2 engine path.
func setCostMetadataV2(ctx *policyv1alpha2.ResponseContext, costUSD float64, status string) policyv1alpha2.ResponseAction {
	if ctx.SharedContext == nil {
		slog.Warn("llm-cost: SharedContext is nil, cannot set cost metadata")
		return policyv1alpha2.DownstreamResponseModifications{}
	}
	if ctx.Metadata == nil {
		ctx.Metadata = make(map[string]interface{})
	}
	ctx.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", costUSD)
	ctx.Metadata[MetadataLLMCostStatus] = status
	return policyv1alpha2.DownstreamResponseModifications{}
}
