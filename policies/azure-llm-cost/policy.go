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

package azurellmcost

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
	streamAccumKey = "azure-llm-cost:stream-accum"
)

const (
	MetadataLLMCost       = "x-llm-cost"
	MetadataLLMCostStatus = "x-llm-cost-status"

	metadataPromptTokenCount     = "aitoken:prompttokencount"
	metadataCompletionTokenCount = "aitoken:completiontokencount"
	metadataTotalTokenCount      = "aitoken:totaltokencount"
	metadataModelID              = "aitoken:modelid"

	metadataTemplateHandle = "template_handle"

	costStatusCalculated    = "calculated"
	costStatusNotCalculated = "not_calculated"
)

// AzureLLMCostPolicy prices Azure OpenAI and Azure AI Foundry responses.
type AzureLLMCostPolicy struct {
	pricingMap map[string]ModelPricing

	// Keyed by lowercased deployment name. Needed because most Azure endpoints
	// echo the deployment rather than the model, and never report the tier.
	modelMappings map[string]deploymentMapping
}

type deploymentMapping struct {
	model  string
	region azureRegion
}

// GetPolicy returns a fresh instance per call, since modelMappings is
// per-attachment. The pricing map itself is cached by file path.
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
	if len(mappings) == 0 {
		slog.Warn("azure-llm-cost: no modelMappings configured; only endpoints that " +
			"report a resolvable model name will be priced under global standard rates")
	}
	slog.Info("azure-llm-cost: policy instance created",
		"pricing_file", pricingFile, "entries", len(pm), "model_mappings", len(mappings))
	return &AzureLLMCostPolicy{pricingMap: pm, modelMappings: mappings}, nil
}

// parseRegion falls back to Global Standard for anything unrecognized.
func parseRegion(raw interface{}) azureRegion {
	s, _ := raw.(string)
	switch r := azureRegion(strings.ToLower(strings.TrimSpace(s))); r {
	case regionUS, regionEU, regionAPAC, regionRegional, regionGlobalStandard:
		return r
	default:
		return regionGlobalStandard
	}
}

// parseModelMappings builds a lookup keyed by the lowercased deployment name.
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

// Streaming also covers buffered responses, delivered as one chunk with
// EndOfStream. The request is buffered so $.model stays readable.
func (p *AzureLLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// NeedsMoreResponseData is always false; chunks are accumulated manually.
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
	result := p.computeCost(body, requestBody, respCtx.RequestPath, templateHandleFrom(respCtx.SharedContext))
	setCostMetadata(respCtx.SharedContext, result)
	return policy.DownstreamResponseModifications{AnalyticsMetadata: analyticsFor(result)}
}

// OnResponseBodyChunk accumulates chunks and prices at end of stream.
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

	result := p.computeCost(accumulated, requestBody, respCtx.RequestPath, templateHandleFrom(respCtx.SharedContext))
	setCostMetadata(respCtx.SharedContext, result)

	return policy.ForwardResponseChunk{AnalyticsMetadata: analyticsFor(result)}
}

// analyticsFor builds the analytics metadata both response phases publish, so a
// streamed and a buffered response report the same fields.
func analyticsFor(result costResult) map[string]interface{} {
	metadata := map[string]interface{}{MetadataLLMCost: result.cost}
	if !result.calculated {
		return metadata
	}
	metadata[metadataModelID] = result.modelKey
	metadata[metadataPromptTokenCount] = strconv.FormatInt(result.usage.TotalInputTokens, 10)
	metadata[metadataCompletionTokenCount] = strconv.FormatInt(result.usage.OutputTokens, 10)
	metadata[metadataTotalTokenCount] = strconv.FormatInt(result.usage.TotalInputTokens+result.usage.OutputTokens, 10)
	return metadata
}

type costResult struct {
	cost       float64
	modelKey   string
	usage      Usage
	calculated bool
}

// computeCost never errors; every failure yields an uncalculated result.
func (p *AzureLLMCostPolicy) computeCost(responseBody, requestBody []byte, requestPath, templateHandle string) costResult {
	if len(responseBody) == 0 {
		slog.Warn("azure-llm-cost: empty response body, skipping cost calculation")
		return costResult{}
	}

	normalized, err := normalizeStreamBody(responseBody)
	if err != nil {
		slog.Warn("azure-llm-cost: failed to prepare response body", "error", err)
		return costResult{}
	}

	pricing, key, candidates, found := p.resolvePricing(normalized, requestBody, requestPath, templateHandle)
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

// resolvePricing takes the model name from the first source that resolves:
//
//  1. response body's model   real model on chat completions, deployment on v1 /responses
//  2. request body's model    deployment name, v1 surface
//  3. deployment path segment legacy surface only
//
// Each is tried through its mapping first, so an operator can correct a
// deployment whose name collides with a real model. Candidates are returned for
// logging when nothing resolves.
func (p *AzureLLMCostPolicy) resolvePricing(responseBody, requestBody []byte, requestPath, templateHandle string) (ModelPricing, string, []string, bool) {
	if !isAzureTemplate(templateHandle) {
		logNonAzureTemplate(templateHandle)
		return ModelPricing{}, "", nil, false
	}
	prefixes := namespacesFor(templateHandle, p.regionForRequest(requestBody, requestPath))

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

// templateHandleFrom reads the handle the kernel records for the route.
func templateHandleFrom(sharedCtx *policy.SharedContext) string {
	if sharedCtx == nil || sharedCtx.Metadata == nil {
		return ""
	}
	handle, _ := sharedCtx.Metadata[metadataTemplateHandle].(string)
	return handle
}

// regionForRequest returns the deployment's tier, or Global Standard.
func (p *AzureLLMCostPolicy) regionForRequest(requestBody []byte, requestPath string) azureRegion {
	var unmapped []string
	for _, deployment := range []string{extractModelName(requestBody), deploymentFromPath(requestPath)} {
		deployment = strings.ToLower(strings.TrimSpace(deployment))
		if deployment == "" {
			continue
		}
		if m, ok := p.modelMappings[deployment]; ok {
			return m.region
		}
		unmapped = append(unmapped, deployment)
	}
	for _, deployment := range unmapped {
		logUnmappedDeployment(deployment)
	}
	return regionGlobalStandard
}

// nonAzureTemplateSeen keeps logNonAzureTemplate to once per handle.
var nonAzureTemplateSeen sync.Map

// logNonAzureTemplate warns that the route names neither Azure template, so the
// request is left unpriced rather than billed from a guessed catalog.
func logNonAzureTemplate(templateHandle string) {
	if _, seen := nonAzureTemplateSeen.LoadOrStore(templateHandle, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: route does not use an Azure provider template, not pricing request",
		"template_handle", templateHandle,
		"expected", templateAzureOpenAI+" or "+templateAzureAI)
}

// unmappedDeploymentSeen keeps logUnmappedDeployment to once per deployment.
var unmappedDeploymentSeen sync.Map

// logUnmappedDeployment warns that no mapping matched, so the tier fell back to
// Global Standard.
func logUnmappedDeployment(deployment string) {
	if _, seen := unmappedDeploymentSeen.LoadOrStore(deployment, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: deployment not found in modelMappings, "+
		"billing at global standard rates",
		"deployment", deployment)
}

// setCostMetadata publishes the cost and its status for downstream policies.
func setCostMetadata(sharedCtx *policy.SharedContext, result costResult) {
	if sharedCtx == nil {
		slog.Warn("azure-llm-cost: SharedContext is nil, cannot set cost metadata")
		return
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
}

// extractModelName reads $.model, or $.message.model for Anthropic streams.
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

// deploymentFromPath reads {deployment} from /openai/deployments/{deployment}/...
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

func isSSEContent(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// normalizeStreamBody merges SSE events so the parsers work on either shape.
func normalizeStreamBody(body []byte) ([]byte, error) {
	if isSSEContent(body) {
		return mergeSSEEvents(body)
	}
	return body, nil
}

// mergeSSEEvents shallow-merges top-level keys, later events winning, and
// deep-merges "usage". Later-wins matters: Azure's first chunk has an empty
// "model" that later chunks replace.
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
			// A later null or blank must not erase what an earlier event supplied.
			// Azure's trailing filter chunks repeat "model" blank and "usage" null.
			if v == nil || v == "" {
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
