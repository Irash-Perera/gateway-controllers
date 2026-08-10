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

import "encoding/json"

// Usage holds token counts normalized from a response's usage object.
//
// TotalInputTokens is the full input token count including any cached or
// cache-write tokens — this is what the 272k long-context tier is measured
// against and what is published to analytics.
type Usage struct {
	TotalInputTokens int64
	OutputTokens     int64

	// CachedReadTokens is the subset of TotalInputTokens billed at the
	// discounted cache-read rate.
	CachedReadTokens int64

	// CacheWriteTokens / CacheWrite1hrTokens are the subsets of
	// TotalInputTokens billed at the cache-creation rate (Anthropic-style
	// caching only — both are 0 for Azure OpenAI, which never charges for
	// cache writes). CacheWrite1hrTokens covers the extended 1-hour TTL.
	CacheWriteTokens    int64
	CacheWrite1hrTokens int64

	// IsPriority reflects a service_tier of "priority", reported either beside
	// the usage object or within it.
	IsPriority bool
}

// cachedTokenDetails is the shape of the *_details sub-objects that report how
// many input tokens were served from cache.
type cachedTokenDetails struct {
	CachedTokens int64 `json:"cached_tokens"`
}

// rawUsage covers every usage-object variant seen across the Azure endpoints,
// verified against live responses:
//
//	prompt_tokens / completion_tokens + prompt_tokens_details   — chat completions
//	prompt_tokens / completion_tokens + prompt_token_details    — assistants thread runs
//	                                    (note the singular "token")
//	input_tokens  / output_tokens     + input_tokens_details    — responses API
//	input_tokens  / output_tokens     + cache_read_input_tokens — Anthropic-style
//	                                    (Foundry Claude)
//
// The first three report a cached-token count that is already included in the
// input total; the Anthropic variant reports cache tokens separately from
// input_tokens, so they must be added. normalizeUsage handles both conventions.
//
// The Anthropic variant also reports reasoning under
// output_tokens_details.thinking_tokens and the routing geography under
// inference_geo. Neither is read: thinking tokens are already part of
// output_tokens, and no Azure entry carries a reasoning rate or the geographic
// multipliers that inference_geo selects.
type rawUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`

	PromptTokensDetails *cachedTokenDetails `json:"prompt_tokens_details"`
	PromptTokenDetails  *cachedTokenDetails `json:"prompt_token_details"`
	InputTokensDetails  *cachedTokenDetails `json:"input_tokens_details"`

	// Anthropic-style caching: these are additive to input_tokens.
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreation            *struct {
		Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
		Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`

	// Anthropic-style responses carry the service tier inside the usage object
	// rather than beside it. normalizeUsage accepts either position.
	ServiceTier string `json:"service_tier"`
}

// priorityServiceTier is the service_tier value that selects priority rates.
// The standard tier is reported as "default" by Azure OpenAI and "standard" by
// Anthropic-style responses; both are simply not this value.
const priorityServiceTier = "priority"

// normalizeUsage extracts token counts from a response body, accepting any of
// the usage-object variants documented on rawUsage. A response with no usage
// object yields a zero Usage and no error — callers treat that as unpriceable.
func normalizeUsage(responseBody []byte) (Usage, error) {
	var resp struct {
		ServiceTier string    `json:"service_tier"`
		Usage       *rawUsage `json:"usage"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return Usage{}, err
	}
	if resp.Usage == nil {
		return Usage{}, nil
	}
	u := resp.Usage

	inputTokens := u.PromptTokens
	if inputTokens == 0 {
		inputTokens = u.InputTokens
	}
	outputTokens := u.CompletionTokens
	if outputTokens == 0 {
		outputTokens = u.OutputTokens
	}

	// Anthropic-style cache writes, split by TTL when the breakdown is given.
	var cacheWrite5m, cacheWrite1hr int64
	if u.CacheCreation != nil {
		cacheWrite5m = u.CacheCreation.Ephemeral5mInputTokens
		cacheWrite1hr = u.CacheCreation.Ephemeral1hInputTokens
	} else {
		cacheWrite5m = u.CacheCreationInputTokens
	}

	usage := Usage{
		OutputTokens: outputTokens,
		IsPriority:   resp.ServiceTier == priorityServiceTier || u.ServiceTier == priorityServiceTier,
	}

	if u.CacheReadInputTokens > 0 || cacheWrite5m > 0 || cacheWrite1hr > 0 {
		// Anthropic-style: input_tokens counts only uncached input, so the
		// cache categories are added on top to get the true input total.
		usage.TotalInputTokens = inputTokens + u.CacheReadInputTokens + cacheWrite5m + cacheWrite1hr
		usage.CachedReadTokens = u.CacheReadInputTokens
		usage.CacheWriteTokens = cacheWrite5m
		usage.CacheWrite1hrTokens = cacheWrite1hr
		return usage, nil
	}

	// Azure OpenAI style: the cached count is already inside the input total,
	// and cache writes are never billed. Accept either spelling of the details
	// object — chat completions uses the plural form, thread runs the singular.
	usage.TotalInputTokens = inputTokens
	for _, d := range []*cachedTokenDetails{u.PromptTokensDetails, u.PromptTokenDetails, u.InputTokensDetails} {
		if d != nil && d.CachedTokens > 0 {
			usage.CachedReadTokens = d.CachedTokens
			break
		}
	}
	return usage, nil
}

// calculateCost computes USD cost from normalized usage and a pricing entry.
// One formula covers both caching styles: Azure OpenAI always has zero
// cache-write tokens, reducing this to
//
//	uncached_input*input + cached_read*cache_read + output*output
//
// while Anthropic-style caching additionally bills the cache-write terms.
// Long-context (>272k) and priority rate overrides are resolved once, gated on
// field presence on the pricing entry rather than on any model name.
func calculateCost(u Usage, p ModelPricing) float64 {
	rates := resolveRates(u.TotalInputTokens, u.IsPriority, p)

	cacheCreate1hr := p.CacheCreationInputTokenCostAbove1hr
	if cacheCreate1hr == 0 {
		cacheCreate1hr = p.CacheCreationInputTokenCost
	}

	uncachedInput := u.TotalInputTokens - u.CachedReadTokens - u.CacheWriteTokens - u.CacheWrite1hrTokens
	if uncachedInput < 0 {
		uncachedInput = 0
	}

	return float64(uncachedInput)*rates.input +
		float64(u.CachedReadTokens)*rates.cacheRead +
		float64(u.CacheWriteTokens)*rates.cacheCreate +
		float64(u.CacheWrite1hrTokens)*cacheCreate1hr +
		float64(u.OutputTokens)*rates.output
}
