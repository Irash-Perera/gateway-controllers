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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
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

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
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

// GetPolicyV2 delegates to GetPolicy.
func GetPolicyV2(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return GetPolicy(metadata, params)
}

// Mode declares the SDK processing requirements:
//   - RequestBodyMode=Buffer: buffer the request so ctx.RequestBody is available
//     in OnResponseBody (needed for Anthropic speed parameter).
//   - ResponseBodyMode=Buffer: buffer the full response body so we can parse
//     the usage object and model name.
func (p *LLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestBodyMode:  policy.BodyModeBuffer,
		ResponseBodyMode: policy.BodyModeBuffer,
	}
}

// OnResponseBody reads the LLM response, looks up model pricing, calculates cost,
// and stores the result in SharedContext.Metadata.
func (p *LLMCostPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present || len(respCtx.ResponseBody.Content) == 0 {
		slog.Warn("llm-cost: empty or missing response body, skipping cost calculation")
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	responseBody := respCtx.ResponseBody.Content

	// If the response body is buffered SSE events rather than a single JSON
	// object, merge all events into one JSON blob so the downstream calculators
	// can parse it with a regular json.Unmarshal.
	if isSSEContent(responseBody) {
		merged, err := mergeSSEEvents(responseBody)
		if err != nil {
			slog.Warn("llm-cost: failed to merge SSE events", "error", err)
			return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
		}
		responseBody = merged
	}

	// Extract model name from response body.
	// Providers place the model name in different locations:
	//   $.model (OpenAI, Anthropic non-streaming, Mistral)
	//   $.modelVersion (Gemini)
	//   $.message.model (Anthropic streaming after SSE merge)
	var probe struct {
		Model        string `json:"model"`
		ModelVersion string `json:"modelVersion"`
		Message      *struct {
			Model string `json:"model"`
		} `json:"message"`
	}
	if err := json.Unmarshal(responseBody, &probe); err != nil {
		slog.Warn("llm-cost: could not parse response body", "error", err)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}
	modelName := probe.Model
	if modelName == "" {
		modelName = probe.ModelVersion
	}
	if modelName == "" && probe.Message != nil {
		modelName = probe.Message.Model
	}
	if modelName == "" {
		slog.Warn("llm-cost: no model name found in response body")
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	// Look up pricing entry.
	pricing, found := lookupPricing(p.pricingMap, modelName)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0", "model", modelName)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	// Select provider calculator.
	calc := selectCalculator(pricing.Provider)
	if calc == nil {
		slog.Warn("llm-cost: unsupported provider, skipping cost calculation", "provider", pricing.Provider, "model", modelName)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	// Get buffered request body (may be nil for providers that don't need it).
	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}

	// Normalize provider-specific usage fields into our common Usage struct.
	usage, err := calc.Normalize(responseBody, requestBody)
	if err != nil {
		slog.Warn("llm-cost: failed to normalize usage", "model", modelName, "error", err)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
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

	return setCostMetadata(respCtx, finalCost, costStatusCalculated)
}

// isSSEContent reports whether the body looks like buffered SSE data (has at
// least one "data: " line).
func isSSEContent(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// mergeSSEEvents parses every SSE data/event line as JSON and shallow-merges all
// top-level keys into a single object (later events win). This produces a
// JSON blob that contains the `model` from early events together with the
// `usage` / `usageMetadata` from the final event, allowing existing
// provider calculators to parse it unchanged.
// The "usage" and "usageMetadata" keys are deep-merged so that fields
// from earlier events (e.g. input_tokens) survive when a later event
// only carries output_tokens.
func mergeSSEEvents(body []byte) ([]byte, error) {
	merged := make(map[string]interface{})

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		var value string
		if strings.HasPrefix(line, sseDataPrefix) {
			value = strings.TrimPrefix(line, sseDataPrefix)
		} else if strings.HasPrefix(line, sseEventPrefix) {
			value = strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
		} else {
			continue
		}
		value = strings.TrimSpace(value)
		if value == sseDone || value == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(value), &event); err != nil {
			continue // skip non-JSON lines
		}

		for k, v := range event {
			// Deep-merge "usage" and "usageMetadata" maps so that fields
			// from earlier events (e.g. input_tokens) survive when a later
			// event only carries output_tokens.
			if (k == "usage" || k == "usageMetadata") && v != nil {
				if newMap, ok := v.(map[string]interface{}); ok {
					if existing, ok := merged[k].(map[string]interface{}); ok {
						for ek, ev := range newMap {
							existing[ek] = ev
						}
						continue
					}
				}
			}
			merged[k] = v
		}
	}

	if len(merged) == 0 {
		return nil, fmt.Errorf("no valid SSE events found")
	}

	return json.Marshal(merged)
}

// setCostMetadata writes x-llm-cost and x-llm-cost-status into SharedContext.Metadata
// for the v1alpha2 engine path.
func setCostMetadata(respCtx *policy.ResponseContext, costUSD float64, status string) policy.ResponseAction {
	if respCtx.SharedContext == nil {
		slog.Warn("llm-cost: SharedContext is nil, cannot set cost metadata")
		return policy.DownstreamResponseModifications{}
	}
	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}
	respCtx.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", costUSD)
	respCtx.Metadata[MetadataLLMCostStatus] = status
	return policy.DownstreamResponseModifications{
		AnalyticsMetadata: map[string]interface{}{
			MetadataLLMCost: costUSD,
		},
	}
}
