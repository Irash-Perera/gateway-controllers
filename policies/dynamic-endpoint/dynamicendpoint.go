// Package dynamicendpoint provides a policy for dynamic upstream routing.
// It demonstrates the UpstreamName functionality in the SDK.
package dynamicendpoint

import (
	"log/slog"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// DynamicEndpointPolicy routes requests to a dynamically specified upstream.
type DynamicEndpointPolicy struct {
	targetUpstream string
}

// GetPolicy is the v1alpha factory entry point (loaded by v1alpha kernels).
// The returned concrete type also satisfies policyv1alpha2 phase interfaces
// (StreamingResponsePolicy, RequestPolicy, ResponsePolicy), so v1alpha2 kernels
// can discover those capabilities via type assertions even when using this factory.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	slog.Debug("[Dynamic Endpoint]: GetPolicy called")

	targetUpstream, _ := params["targetUpstream"].(string)

	return &DynamicEndpointPolicy{
		targetUpstream: targetUpstream,
	}, nil
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

// Mode returns the processing mode for this policy.
func (p *DynamicEndpointPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Need headers to process the request
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequest sets the dynamic upstream for routing.
func (p *DynamicEndpointPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	slog.Info("[Dynamic Endpoint]: OnRequest called", "targetUpstream", p.targetUpstream)

	if p.targetUpstream == "" {
		slog.Warn("[Dynamic Endpoint]: No target upstream configured, passing through")
		return policy.UpstreamRequestModifications{}
	}

	// Use UpstreamName to route the request to the target upstream definition
	// The upstream name must match an entry in the API's upstreamDefinitions
	return policy.UpstreamRequestModifications{
		UpstreamName: &p.targetUpstream,
	}
}

// OnResponse is not used by this policy.
func (p *DynamicEndpointPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return policy.UpstreamResponseModifications{}
}

// OnRequestHeaders routes the request to the configured upstream.
func (p *DynamicEndpointPolicy) OnRequestHeaders(ctx *policyv1alpha2.RequestHeaderContext, params map[string]interface{}) policyv1alpha2.RequestHeaderAction {
	slog.Info("[Dynamic Endpoint]: OnRequestHeaders called", "targetUpstream", p.targetUpstream)

	if p.targetUpstream == "" {
		slog.Warn("[Dynamic Endpoint]: No target upstream configured, passing through")
		return policyv1alpha2.UpstreamRequestHeaderModifications{}
	}

	// Use UpstreamName to route the request to the target upstream definition.
	// The upstream name must match an entry in the API's upstreamDefinitions.
	return policyv1alpha2.UpstreamRequestHeaderModifications{
		UpstreamName: &p.targetUpstream,
	}
}
