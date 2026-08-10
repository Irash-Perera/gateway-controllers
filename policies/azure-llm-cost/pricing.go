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
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	pricingCache   = map[string]map[string]ModelPricing{}
	pricingCacheMu sync.RWMutex
)

// loadPricingFromFile reads the pricing JSON file at path and returns a map
// of model key -> ModelPricing, restricted to "azure/" and
// "azure_ai/" prefixed keys. Results are cached at the package level by file
// path; a gateway restart is required to pick up changes to the pricing file.
func loadPricingFromFile(path string) (map[string]ModelPricing, error) {
	pricingCacheMu.RLock()
	if pm, ok := pricingCache[path]; ok {
		pricingCacheMu.RUnlock()
		return pm, nil
	}
	pricingCacheMu.RUnlock()

	pm, err := loadPricingFromDisk(path)
	if err != nil {
		return nil, err
	}

	pricingCacheMu.Lock()
	pricingCache[path] = pm
	pricingCacheMu.Unlock()
	return pm, nil
}

func loadPricingFromDisk(path string) (map[string]ModelPricing, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse pricing file: %w", err)
	}

	pm := make(map[string]ModelPricing)
	for key, msg := range raw {
		if !strings.HasPrefix(key, "azure/") && !strings.HasPrefix(key, "azure_ai/") {
			continue
		}
		var p ModelPricing
		if err := json.Unmarshal(msg, &p); err != nil {
			slog.Warn("azure-llm-cost: skipping invalid pricing entry", "key", key, "error", err)
			continue
		}
		// Source keys aren't consistently cased (e.g. "azure_ai/Llama-3.3-70B-Instruct"),
		// but lookupPricingWithKey lowercases every candidate it builds — normalize here
		// so lookups are consistently case-insensitive.
		pm[strings.ToLower(key)] = p
	}
	if len(pm) == 0 {
		return nil, fmt.Errorf("pricing file has no azure/ or azure_ai/ entries: %s", path)
	}
	return pm, nil
}

// ModelPricing holds the cost rate fields this policy uses for a single
// pricing entry. This policy shares its pricing_file with the llm-cost
// policy — both point their pricing_file system parameter at the same
// gateway-provided pricing JSON (/etc/policy-engine/llm-pricing/model_prices.json).
// Field names here match that shared file's schema; only fields relevant to
// Azure OpenAI / Azure AI Foundry text-token billing are parsed — every
// other field (max_input_tokens, mode, etc.) is ignored.
type ModelPricing struct {
	// Provider is the pricing file's own namespace tag ("azure", "azure_ai",
	// or the legacy "azure_text" for Azure OpenAI's completions-API models).
	// It is informational only — which usage-parsing path runs is decided by
	// which key namespace resolution matched (see lookupPricingWithKey), not by
	// this field, so "azure_text" entries are handled identically to "azure".
	Provider string `json:"provider"`

	InputCostPerToken  float64 `json:"input_cost_per_token"`
	OutputCostPerToken float64 `json:"output_cost_per_token"`

	// Prompt caching. CacheReadInputTokenCost alone means read-only caching
	// (Azure OpenAI, Foundry GPT): reads are discounted, writes are free.
	// CacheCreationInputTokenCost additionally present means Anthropic-style
	// caching (Foundry Claude): writes are billed too.
	CacheReadInputTokenCost             float64 `json:"cache_read_input_token_cost"`
	CacheCreationInputTokenCost         float64 `json:"cache_creation_input_token_cost"`
	CacheCreationInputTokenCostAbove1hr float64 `json:"cache_creation_input_token_cost_above_1hr"`

	// Long-context tier (>272k input tokens). Overrides the base rate only
	// when the corresponding field is present and the request qualifies.
	InputCostPerTokenAbove272k       float64 `json:"input_cost_per_token_above_272k_tokens"`
	OutputCostPerTokenAbove272k      float64 `json:"output_cost_per_token_above_272k_tokens"`
	CacheReadInputTokenCostAbove272k float64 `json:"cache_read_input_token_cost_above_272k_tokens"`

	// Priority service tier. Overrides the base rate only when the
	// corresponding field is present and the response reports priority tier.
	InputCostPerTokenPriority       float64 `json:"input_cost_per_token_priority"`
	OutputCostPerTokenPriority      float64 `json:"output_cost_per_token_priority"`
	CacheReadInputTokenCostPriority float64 `json:"cache_read_input_token_cost_priority"`

	// Combined long-context + priority tier. Takes precedence over the plain
	// above-272k rate when both conditions hold and this field is present.
	InputCostPerTokenAbove272kPriority       float64 `json:"input_cost_per_token_above_272k_tokens_priority"`
	OutputCostPerTokenAbove272kPriority      float64 `json:"output_cost_per_token_above_272k_tokens_priority"`
	CacheReadInputTokenCostAbove272kPriority float64 `json:"cache_read_input_token_cost_above_272k_tokens_priority"`
}

// Unpriced reports whether this entry carries no per-token input rate at
// all — e.g. image, embedding, or rerank entries billed by a different unit.
// Requests resolving to such an entry are treated as unpriceable.
func (p ModelPricing) Unpriced() bool {
	return p.InputCostPerToken == 0 && p.OutputCostPerToken == 0
}

// effectiveRates holds the resolved per-token rates after applying
// long-context tiering and priority-tier overrides.
type effectiveRates struct {
	input       float64
	output      float64
	cacheRead   float64
	cacheCreate float64
}

// resolveRates selects the correct per-token rates for the given usage and
// pricing entry. Long-context (>272k input tokens) and priority-tier
// overrides are each applied only when the corresponding field is present on
// the entry; a request that qualifies for both uses the combined
// "_above_272k_tokens_priority" fields when present, falling back to
// whichever single override is available.
func resolveRates(inputTokensForTiering int64, isPriority bool, pricing ModelPricing) effectiveRates {
	r := effectiveRates{
		input:       pricing.InputCostPerToken,
		output:      pricing.OutputCostPerToken,
		cacheRead:   pricing.CacheReadInputTokenCost,
		cacheCreate: pricing.CacheCreationInputTokenCost,
	}

	aboveTier := inputTokensForTiering > 272_000

	switch {
	case aboveTier && isPriority && pricing.InputCostPerTokenAbove272kPriority > 0:
		r.input = pricing.InputCostPerTokenAbove272kPriority
		if pricing.OutputCostPerTokenAbove272kPriority > 0 {
			r.output = pricing.OutputCostPerTokenAbove272kPriority
		}
		if pricing.CacheReadInputTokenCostAbove272kPriority > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostAbove272kPriority
		}
	case aboveTier && pricing.InputCostPerTokenAbove272k > 0:
		r.input = pricing.InputCostPerTokenAbove272k
		if pricing.OutputCostPerTokenAbove272k > 0 {
			r.output = pricing.OutputCostPerTokenAbove272k
		}
		if pricing.CacheReadInputTokenCostAbove272k > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostAbove272k
		}
	case isPriority && pricing.InputCostPerTokenPriority > 0:
		r.input = pricing.InputCostPerTokenPriority
		if pricing.OutputCostPerTokenPriority > 0 {
			r.output = pricing.OutputCostPerTokenPriority
		}
		if pricing.CacheReadInputTokenCostPriority > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostPriority
		}
	}

	return r
}

// openAIPathSegment marks the OpenAI-compatible API surface. Azure OpenAI
// serves only that surface, while Azure AI Foundry serves it for the OpenAI
// models it hosts and its own "/models/..." surface for everything else.
const openAIPathSegment = "/openai/"

// namespacesFor returns the pricing-key prefixes to search, most likely first.
//
// The two namespaces are separate catalogs — "azure/" holds Azure OpenAI models
// and "azure_ai/" the Foundry-native ones — but a single Foundry resource can
// serve both, so the endpoint host does not determine which applies. The request
// path does: an OpenAI-compatible path indicates an Azure OpenAI model whichever
// resource served it.
//
// Both namespaces are always searched. The order only decides which wins for a
// model name that appears in both, and the path is the better guide to that.
func namespacesFor(requestPath string, region azureRegion) []string {
	if region == "" {
		region = regionGlobalStandard
	}
	azureOpenAI := []string{"azure/" + string(region) + "/", "azure/"}
	foundry := []string{"azure_ai/"}

	if strings.Contains(strings.ToLower(requestPath), openAIPathSegment) {
		return append(azureOpenAI, foundry...)
	}
	return append(foundry, azureOpenAI...)
}

// azureRegion identifies the Azure deployment type whose key prefix is tried
// first when resolving a model. The values mirror Azure's pay-per-token
// deployment types; provisioned (PTU) types bill reserved capacity rather than
// tokens, so they are not represented:
//
//	global-standard  Global Standard    — any region; Azure's default
//	us / eu / apac   Data Zone Standard — pinned to that data zone
//	regional         Standard           — pinned to a single region
//
// Configured per deployment, since the deployment type is chosen per deployment
// rather than per resource. Only meaningful for Azure OpenAI; Azure AI Foundry
// has no tier-scoped pricing.
type azureRegion string

const (
	regionGlobalStandard azureRegion = "global-standard"
	regionUS             azureRegion = "us"
	regionEU             azureRegion = "eu"
	regionAPAC           azureRegion = "apac"
	regionRegional       azureRegion = "regional"
)

// lookupPricingWithKey resolves a model name to a pricing entry and the key that
// matched it, searching the given namespace prefixes in order. The name must
// match a key exactly; there is no partial matching, so a model the file does
// not carry is reported unresolved rather than billed at a near neighbour's rate.
//
// The pricing file is customer-maintained, so this order is the policy's
// published contract: adding an "azure/<region>/<model>" key is how an operator
// makes a tier-specific rate take effect.
func lookupPricingWithKey(pricingMap map[string]ModelPricing, modelName string, prefixes []string) (ModelPricing, string, bool) {
	modelName = strings.ToLower(strings.TrimSpace(modelName))
	if modelName == "" {
		return ModelPricing{}, "", false
	}
	for _, prefix := range prefixes {
		if p, ok := pricingMap[prefix+modelName]; ok {
			logTierFallback(prefixes, modelName, prefix)
			return p, prefix + modelName, true
		}
	}
	return ModelPricing{}, "", false
}

// tierFallbackSeen records the (region, model) pairs already reported by
// logTierFallback, so a misconfigured tier is surfaced once rather than on
// every request.
var tierFallbackSeen sync.Map

// logTierFallback reports that a tier-specific pricing entry was requested but
// not found, so the unprefixed base entry was billed instead. The rates differ
// between tiers, so this is worth surfacing — the fix is to add an
// "azure/<region>/<model>" key to the pricing file.
//
// The default global-standard tier is deliberately silent: the base entries
// already hold Global Standard rates.
func logTierFallback(prefixes []string, modelName, matchedPrefix string) {
	if matchedPrefix != "azure/" {
		return
	}
	var tierPrefix string
	for _, p := range prefixes {
		if strings.HasPrefix(p, "azure/") && p != "azure/" {
			tierPrefix = p
			break
		}
	}
	if tierPrefix == "" || tierPrefix == "azure/"+string(regionGlobalStandard)+"/" {
		return
	}
	if _, seen := tierFallbackSeen.LoadOrStore(tierPrefix+"|"+modelName, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: no pricing entry for the configured tier, billing at the base rate",
		"model", modelName,
		"missing_key", tierPrefix+modelName,
		"used_key", "azure/"+modelName)
}
