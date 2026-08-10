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

// Package azurellmcost calculates the monetary cost of LLM requests routed to
// Azure OpenAI Service ("azure/...") and Azure AI Foundry ("azure_ai/...") from
// the token usage returned in the upstream response. It is independent of, and
// shares no code with, the llm-cost policy.
package azurellmcost

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"

	// streamAccumKey is the per-request metadata key used to accumulate
	// streaming response chunks, namespaced so it cannot collide with another
	// policy's accumulator.
	streamAccumKey = "azure-llm-cost:stream-accum"
)

const (
	// These metadata keys intentionally match the ones llm-cost writes, so
	// downstream consumers (llm-cost-based-ratelimit, the analytics publisher)
	// work unchanged regardless of which cost policy ran. A route is expected
	// to attach at most one of the two.
	MetadataLLMCost       = "x-llm-cost"
	MetadataLLMCostStatus = "x-llm-cost-status"

	metadataPromptTokenCount     = "aitoken:prompttokencount"
	metadataCompletionTokenCount = "aitoken:completiontokencount"
	metadataTotalTokenCount      = "aitoken:totaltokencount"
	metadataModelID              = "aitoken:modelid"

	costStatusCalculated    = "calculated"
	costStatusNotCalculated = "not_calculated"
)

// AzureLLMCostPolicy calculates LLM cost for Azure OpenAI and Azure AI Foundry
// responses and stores the result in SharedContext.Metadata.
type AzureLLMCostPolicy struct {
	pricingMap map[string]ModelPricing

	// modelMappings describes each Azure deployment the route can reach, keyed
	// by the lowercased deployment name. The model is needed because most Azure
	// endpoints echo the deployment name rather than the underlying model (chat
	// completions is the exception — it reports the real model). The region is
	// the deployment's pricing tier, which Azure never reports.
	modelMappings map[string]deploymentMapping
}

// deploymentMapping is the operator's description of one deployment.
type deploymentMapping struct {
	model  string
	region azureRegion
}

// GetPolicy is the v1alpha2 factory entry point. A fresh instance is returned
// per call because region and modelMappings are per-attachment parameters. The
// pricing map itself is loaded once and cached by file path, so many instances
// can share the same pricing_file without reloading it.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	pricingFile, _ := params["pricing_file"].(string)
	if pricingFile == "" {
		return nil, fmt.Errorf("azure-llm-cost: pricing_file system parameter is required but not set")
	}
	pm, err := loadPricingFromFile(pricingFile)
	if err != nil {
		return nil, fmt.Errorf("azure-llm-cost: failed to load pricing file %q: %w", pricingFile, err)
	}
	mappings, err := parseModelMappings(params["modelMappings"])
	if err != nil {
		return nil, fmt.Errorf("azure-llm-cost: invalid modelMappings: %w", err)
	}
	// modelMappings is declared required in the policy schema, but an absent or
	// empty value is not treated as fatal here: failing instance creation would
	// tear down the whole route's policy chain and 500 every request on it.
	// Costing simply falls back to whatever model name the response reports.
	if len(mappings) == 0 {
		slog.Warn("azure-llm-cost: no modelMappings configured; only endpoints that " +
			"report a resolvable model name (chat completions) will be priced")
	}
	slog.Info("azure-llm-cost: policy instance created",
		"pricing_file", pricingFile, "entries", len(pm), "model_mappings", len(mappings))
	return &AzureLLMCostPolicy{pricingMap: pm, modelMappings: mappings}, nil
}

// parseRegion reads a mapping entry's region. Anything unset or unrecognized
// falls back to Global Standard, Azure's own default deployment type.
func parseRegion(raw interface{}) azureRegion {
	s, _ := raw.(string)
	switch r := azureRegion(strings.ToLower(strings.TrimSpace(s))); r {
	case regionUS, regionEU, regionAPAC, regionRegional, regionGlobalStandard:
		return r
	default:
		return regionGlobalStandard
	}
}

// parseModelMappings reads the modelMappings parameter, an array of
// {deployment, model, region} objects, into a lookup map keyed by the
// lowercased deployment name.
func parseModelMappings(raw interface{}) (map[string]deploymentMapping, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected an array, got %T", raw)
	}
	mappings := make(map[string]deploymentMapping, len(list))
	for i, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("entry %d: expected an object, got %T", i, item)
		}
		deployment, _ := entry["deployment"].(string)
		model, _ := entry["model"].(string)
		deployment = strings.ToLower(strings.TrimSpace(deployment))
		model = strings.TrimSpace(model)
		if deployment == "" || model == "" {
			return nil, fmt.Errorf("entry %d: both 'deployment' and 'model' are required", i)
		}
		mappings[deployment] = deploymentMapping{model: model, region: parseRegion(entry["region"])}
	}
	return mappings, nil
}

// Mode declares streaming response processing (which also covers buffered
// responses — the kernel delivers those as a single chunk with EndOfStream) and
// buffered request processing, needed to fall back to the request body's
// $.model when the response does not carry a usable one.
func (p *AzureLLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// NeedsMoreResponseData always returns false; chunks are accumulated manually.
func (p *AzureLLMCostPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBody handles the buffered fallback path.
func (p *AzureLLMCostPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}
	var body []byte
	if respCtx.ResponseBody != nil && respCtx.ResponseBody.Present {
		body = respCtx.ResponseBody.Content
	}
	result := p.computeCost(body, requestBody, respCtx.RequestPath)
	return setCostMetadata(respCtx.SharedContext, result)
}

// OnResponseBodyChunk accumulates streaming chunks and computes cost at
// end-of-stream.
func (p *AzureLLMCostPolicy) OnResponseBodyChunk(
	_ context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if len(chunk.Chunk) > 0 {
		if respCtx.Metadata == nil {
			respCtx.Metadata = make(map[string]interface{})
		}
		existing, _ := respCtx.Metadata[streamAccumKey].([]byte)
		respCtx.Metadata[streamAccumKey] = append(existing, chunk.Chunk...)
	}

	if !chunk.EndOfStream {
		return policy.ForwardResponseChunk{}
	}

	var accumulated []byte
	if respCtx.Metadata != nil {
		accumulated, _ = respCtx.Metadata[streamAccumKey].([]byte)
		delete(respCtx.Metadata, streamAccumKey)
	}
	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}

	result := p.computeCost(accumulated, requestBody, respCtx.RequestPath)
	setCostMetadata(respCtx.SharedContext, result)

	analyticsMetadata := map[string]any{MetadataLLMCost: result.cost}
	if result.calculated {
		analyticsMetadata[metadataModelID] = result.modelKey
		analyticsMetadata[metadataPromptTokenCount] = strconv.FormatInt(result.usage.TotalInputTokens, 10)
		analyticsMetadata[metadataCompletionTokenCount] = strconv.FormatInt(result.usage.OutputTokens, 10)
		analyticsMetadata[metadataTotalTokenCount] = strconv.FormatInt(result.usage.TotalInputTokens+result.usage.OutputTokens, 10)
	}
	return policy.ForwardResponseChunk{AnalyticsMetadata: analyticsMetadata}
}

type costResult struct {
	cost       float64
	modelKey   string
	usage      Usage
	calculated bool
}

// computeCost resolves the model, looks up pricing, parses usage and computes
// cost. Any failure (empty body, unparseable JSON, unresolvable model,
// unpriceable entry, missing usage) yields a zero-valued uncalculated result —
// never an error, and never a change to the proxied response.
func (p *AzureLLMCostPolicy) computeCost(responseBody, requestBody []byte, requestPath string) costResult {
	if len(responseBody) == 0 {
		slog.Warn("azure-llm-cost: empty response body, skipping cost calculation")
		return costResult{}
	}

	normalized, err := normalizeStreamBody(responseBody)
	if err != nil {
		slog.Warn("azure-llm-cost: failed to prepare response body", "error", err)
		return costResult{}
	}

	pricing, key, candidates, found := p.resolvePricing(normalized, requestBody, requestPath)
	if !found {
		slog.Warn("azure-llm-cost: model not found for costing, request not priced",
			"candidates", strings.Join(candidates, ","))
		return costResult{}
	}
	if pricing.Unpriced() {
		slog.Warn("azure-llm-cost: model has no per-token pricing, request not priced", "model", key)
		return costResult{}
	}

	usage, err := normalizeUsage(normalized)
	if err != nil {
		slog.Warn("azure-llm-cost: failed to parse usage object", "model", key, "error", err)
		return costResult{}
	}
	if usage.TotalInputTokens == 0 && usage.OutputTokens == 0 {
		slog.Warn("azure-llm-cost: response has no usage data, request not priced", "model", key)
		return costResult{}
	}

	cost := calculateCost(usage, pricing)
	slog.Debug("azure-llm-cost: calculated cost",
		"model", key,
		"input_tokens", usage.TotalInputTokens, "output_tokens", usage.OutputTokens,
		"cached_tokens", usage.CachedReadTokens, "cost_usd", cost,
	)
	return costResult{cost: cost, modelKey: key, usage: usage, calculated: true}
}

// resolvePricing finds the pricing entry for a request.
//
// The deployment and the model name are resolved independently. The deployment
// is always identifiable — from the path on the legacy API surface, from the
// request body's "model" on the v1 surface — and its mapping entry supplies the
// pricing tier, which Azure never reports. The model name is then taken from
// the highest-authority source available:
//
//  1. the response body's model — the resolved underlying model on chat
//     completions (both surfaces), but the deployment name on v1 /responses
//  2. the request body's model — the deployment name on the v1 surface
//  3. the deployment segment of the request path — the legacy surface only
//
// Each candidate is resolved through its mapping before a direct lookup, so an
// operator can correct a deployment whose name collides with a real model name,
// while a higher-authority candidate is never displaced by a lower one's
// mapping.
//
// The namespaces searched, and their order, come from the request path — see
// namespacesFor.
//
// The candidate list is returned for logging when nothing resolves.
func (p *AzureLLMCostPolicy) resolvePricing(responseBody, requestBody []byte, requestPath string) (ModelPricing, string, []string, bool) {
	prefixes := namespacesFor(requestPath, p.regionForRequest(requestBody, requestPath))

	var candidates []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		for _, existing := range candidates {
			if strings.EqualFold(existing, name) {
				return
			}
		}
		candidates = append(candidates, name)
	}
	add(extractModelName(responseBody))
	add(extractModelName(requestBody))
	add(deploymentFromPath(requestPath))

	for _, name := range candidates {
		if mapped, ok := p.modelMappings[strings.ToLower(name)]; ok {
			if pricing, key, found := lookupPricingWithKey(p.pricingMap, mapped.model, prefixes); found {
				return pricing, key, candidates, true
			}
			slog.Warn("azure-llm-cost: mapped model has no pricing entry",
				"deployment", name, "mapped_model", mapped.model)
		}
		if pricing, key, found := lookupPricingWithKey(p.pricingMap, name, prefixes); found {
			return pricing, key, candidates, true
		}
	}
	return ModelPricing{}, "", candidates, false
}

// regionForRequest returns the pricing tier of the deployment this request
// targeted. The deployment is named in the request body on the v1 API surface
// and in the path on the legacy one; a deployment absent from modelMappings
// falls back to Global Standard.
func (p *AzureLLMCostPolicy) regionForRequest(requestBody []byte, requestPath string) azureRegion {
	for _, deployment := range []string{extractModelName(requestBody), deploymentFromPath(requestPath)} {
		if deployment == "" {
			continue
		}
		if m, ok := p.modelMappings[strings.ToLower(strings.TrimSpace(deployment))]; ok {
			return m.region
		}
	}
	return regionGlobalStandard
}

func setCostMetadata(sharedCtx *policy.SharedContext, result costResult) policy.ResponseAction {
	if sharedCtx == nil {
		slog.Warn("azure-llm-cost: SharedContext is nil, cannot set cost metadata")
		return policy.DownstreamResponseModifications{}
	}
	if sharedCtx.Metadata == nil {
		sharedCtx.Metadata = make(map[string]interface{})
	}
	status := costStatusNotCalculated
	if result.calculated {
		status = costStatusCalculated
	}
	sharedCtx.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", result.cost)
	sharedCtx.Metadata[MetadataLLMCostStatus] = status
	return policy.DownstreamResponseModifications{
		AnalyticsMetadata: map[string]interface{}{MetadataLLMCost: result.cost},
	}
}

// extractModelName reads a model name from $.model, or $.message.model for the
// Anthropic streaming envelope (present after SSE merging).
func extractModelName(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var probe struct {
		Model   string `json:"model"`
		Message *struct {
			Model string `json:"model"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	if probe.Model != "" {
		return probe.Model
	}
	if probe.Message != nil {
		return probe.Message.Model
	}
	return ""
}

// deploymentFromPath extracts the deployment segment from an Azure OpenAI
// request path such as /openai/deployments/{deployment}/chat/completions.
func deploymentFromPath(requestPath string) string {
	const marker = "/deployments/"
	i := strings.Index(requestPath, marker)
	if i < 0 {
		return ""
	}
	rest := requestPath[i+len(marker):]
	if end := strings.IndexAny(rest, "/?"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// isSSEContent reports whether the body looks like SSE data.
func isSSEContent(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// normalizeStreamBody merges SSE events into a single JSON object so the model
// and usage parsers work unchanged on streamed and buffered responses alike.
func normalizeStreamBody(body []byte) ([]byte, error) {
	if isSSEContent(body) {
		return mergeSSEEvents(body)
	}
	return body, nil
}

// mergeSSEEvents parses each SSE data/event line as JSON and shallow-merges the
// top-level keys into one object (later events win), deep-merging "usage" so
// fields split across events survive. Later-wins matters in practice: Azure's
// first chat-completions chunk carries an empty "model", which subsequent
// chunks overwrite with the real model name.
func mergeSSEEvents(body []byte) ([]byte, error) {
	var events [][]byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		var value string
		switch {
		case strings.HasPrefix(line, sseDataPrefix):
			value = strings.TrimPrefix(line, sseDataPrefix)
		case strings.HasPrefix(line, sseEventPrefix):
			value = strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
		default:
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" || value == sseDone || !json.Valid([]byte(value)) {
			continue
		}
		events = append(events, []byte(value))
	}
	return mergeJSONEvents(events)
}

func mergeJSONEvents(events [][]byte) ([]byte, error) {
	merged := make(map[string]interface{})
	for _, data := range events {
		var event map[string]interface{}
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		for k, v := range event {
			if k == "usage" && v != nil {
				if newMap, ok := v.(map[string]interface{}); ok {
					if existing, ok := merged[k].(map[string]interface{}); ok {
						for ek, ev := range newMap {
							existing[ek] = ev
						}
						continue
					}
				}
			}
			// Skip empty strings so an early chunk's blank "model" cannot
			// overwrite a real value set by a later chunk out of order.
			if s, ok := v.(string); ok && s == "" {
				if _, exists := merged[k]; exists {
					continue
				}
			}
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return nil, fmt.Errorf("no valid JSON events found")
	}
	return json.Marshal(merged)
}
