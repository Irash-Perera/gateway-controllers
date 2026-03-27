// Package dynamicendpoint provides a policy for dynamic upstream routing.
// It demonstrates the UpstreamName functionality in the SDK.
package dynamicendpoint

import (
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// DynamicEndpointPolicy routes requests to a dynamically specified upstream.
type DynamicEndpointPolicy struct {
	targetUpstream string
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
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

// Mode returns the processing mode for this policy.
func (p *DynamicEndpointPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Need headers to process the request
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequestHeaders routes the request to the configured upstream.
func (p *DynamicEndpointPolicy) OnRequestHeaders(ctx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	slog.Info("[Dynamic Endpoint]: OnRequestHeaders called", "targetUpstream", p.targetUpstream)

	if p.targetUpstream == "" {
		slog.Warn("[Dynamic Endpoint]: No target upstream configured, passing through")
		return policy.UpstreamRequestHeaderModifications{}
	}

	// Use UpstreamName to route the request to the target upstream definition.
	// The upstream name must match an entry in the API's upstreamDefinitions.
	return policy.UpstreamRequestHeaderModifications{
		UpstreamName: &p.targetUpstream,
	}
}
