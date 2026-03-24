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

package basicratelimit

import (
	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policyv1alpha "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

// BasicRateLimitPolicy provides a simplified rate limiting policy that delegates
// to the core ratelimit policyv1alpha. It uses routename as the rate limit key and
// does not support cost extraction or multi-quota configurations.
type BasicRateLimitPolicy struct {
	delegate policyv1alpha.Policy
}

// GetPolicy creates and initializes the basic rate limit policyv1alpha.
// It transforms the simple limits configuration to a full ratelimit quota config
// and delegates to the core ratelimit policyv1alpha.
func GetPolicy(
	metadata policyv1alpha.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha.Policy, error) {
	// Transform simple limits to full ratelimit config
	rlParams := transformToRatelimitParams(params, metadata)

	// Create the delegate ratelimit policy
	delegate, err := ratelimit.GetPolicy(metadata, rlParams)
	if err != nil {
		return nil, err
	}

	return &BasicRateLimitPolicy{delegate: delegate}, nil
}

// transformToRatelimitParams converts the simple limits array to a full ratelimit
// quota configuration with routename key extraction, and passes through system
// parameters (algorithm, backend, redis, memory).
func transformToRatelimitParams(params map[string]interface{}, metadata policyv1alpha.PolicyMetadata) map[string]interface{} {
	limits, _ := params["limits"].([]interface{})

	// basic-ratelimit uses `requests` while advanced-ratelimit expects `limit`.
	// Translate each limit entry before delegating.
	transformedLimits := make([]interface{}, 0, len(limits))
	for _, entry := range limits {
		limitMap, ok := entry.(map[string]interface{})
		if !ok {
			transformedLimits = append(transformedLimits, entry)
			continue
		}

		translated := make(map[string]interface{}, len(limitMap))
		for k, v := range limitMap {
			translated[k] = v
		}

		if requests, ok := translated["requests"]; ok {
			translated["limit"] = requests
			delete(translated, "requests")
		}

		transformedLimits = append(transformedLimits, translated)
	}

	keyExtractorType := "routename"
	if metadata.AttachedTo == policyv1alpha.LevelAPI {
		keyExtractorType = "apiname"
	}

	rlParams := map[string]interface{}{
		"quotas": []interface{}{
			map[string]interface{}{
				"name":   "default",
				"limits": transformedLimits,
				"keyExtraction": []interface{}{
					map[string]interface{}{
						"type": keyExtractorType,
					},
				},
			},
		},
	}

	// Pass through system parameters
	if algorithm, ok := params["algorithm"]; ok {
		rlParams["algorithm"] = algorithm
	}
	if backend, ok := params["backend"]; ok {
		rlParams["backend"] = backend
	}
	if redis, ok := params["redis"]; ok {
		rlParams["redis"] = redis
	}
	if memory, ok := params["memory"]; ok {
		rlParams["memory"] = memory
	}

	return rlParams
}

// Mode returns the processing mode for this policyv1alpha.
// Since basic-ratelimit does not use cost extraction from request/response bodies,
// it only needs header processing and skips body buffering.
func (p *BasicRateLimitPolicy) Mode() policyv1alpha.ProcessingMode {
	return policyv1alpha.ProcessingMode{
		RequestHeaderMode:  policyv1alpha.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha.BodyModeSkip,
		ResponseHeaderMode: policyv1alpha.HeaderModeProcess,
		ResponseBodyMode:   policyv1alpha.BodyModeSkip,
	}
}

// OnRequestHeaders delegates to the core ratelimit policy's OnRequestHeaders method if available.
func (p *BasicRateLimitPolicy) OnRequestHeaders(
	ctx *policyv1alpha2.RequestHeaderContext,
	params map[string]interface{},
) policyv1alpha2.RequestHeaderAction {
	type requestHeaderPolicer interface {
		OnRequestHeaders(*policyv1alpha2.RequestHeaderContext, map[string]interface{}) policyv1alpha2.RequestHeaderAction
	}
	if rl, ok := p.delegate.(requestHeaderPolicer); ok {
		return rl.OnRequestHeaders(ctx, params)
	}
	return policyv1alpha2.UpstreamRequestHeaderModifications{}
}

// OnRequest delegates to the core ratelimit policy's OnRequest method for v1alpha engine compatibility.
func (p *BasicRateLimitPolicy) OnRequest(
	ctx *policyv1alpha.RequestContext,
	params map[string]interface{},
) policyv1alpha.RequestAction {
	return p.delegate.OnRequest(ctx, params)
}

// OnRequestBody delegates to the core ratelimit policy's OnRequestBody method if available.
func (p *BasicRateLimitPolicy) OnRequestBody(
	ctx *policyv1alpha2.RequestContext,
	params map[string]interface{},
) policyv1alpha2.RequestAction {
	type requestBodyPolicer interface {
		OnRequestBody(*policyv1alpha2.RequestContext, map[string]interface{}) policyv1alpha2.RequestAction
	}
	if rl, ok := p.delegate.(requestBodyPolicer); ok {
		return rl.OnRequestBody(ctx, params)
	}
	return policyv1alpha2.UpstreamRequestModifications{}
}

// OnResponseHeaders delegates to the core ratelimit policy's OnResponseHeaders method if available.
func (p *BasicRateLimitPolicy) OnResponseHeaders(
	ctx *policyv1alpha2.ResponseHeaderContext,
	params map[string]interface{},
) policyv1alpha2.ResponseHeaderAction {
	type responseHeaderPolicer interface {
		OnResponseHeaders(*policyv1alpha2.ResponseHeaderContext, map[string]interface{}) policyv1alpha2.ResponseHeaderAction
	}
	if rl, ok := p.delegate.(responseHeaderPolicer); ok {
		return rl.OnResponseHeaders(ctx, params)
	}
	return policyv1alpha2.DownstreamResponseHeaderModifications{}
}

// OnResponse delegates to the core ratelimit policy's OnResponse method for v1alpha engine compatibility.
func (p *BasicRateLimitPolicy) OnResponse(
	ctx *policyv1alpha.ResponseContext,
	params map[string]interface{},
) policyv1alpha.ResponseAction {
	return p.delegate.OnResponse(ctx, params)
}

// OnResponseBody delegates to the core ratelimit policy's OnResponseBody method if available.
func (p *BasicRateLimitPolicy) OnResponseBody(
	ctx *policyv1alpha2.ResponseContext,
	params map[string]interface{},
) policyv1alpha2.ResponseAction {
	type responseBodyPolicer interface {
		OnResponseBody(*policyv1alpha2.ResponseContext, map[string]interface{}) policyv1alpha2.ResponseAction
	}
	if rl, ok := p.delegate.(responseBodyPolicer); ok {
		return rl.OnResponseBody(ctx, params)
	}
	return policyv1alpha2.DownstreamResponseModifications{}
}
