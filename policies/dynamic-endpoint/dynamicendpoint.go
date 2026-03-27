// Package dynamicendpoint provides a policy for dynamic upstream routing.
// It demonstrates the UpstreamName functionality in the SDK.
package dynamicendpoint

import (
	"log/slog"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// DynamicEndpointPolicy routes requests to a dynamically specified upstream.
type DynamicEndpointPolicy struct {
	targetUpstream string
}

// GetPolicyV2 is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicyV2(
	metadata policyv1alpha2.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha2.Policy, error) {
	slog.Debug("[Dynamic Endpoint]: GetPolicyV2 called")

	targetUpstream, _ := params["targetUpstream"].(string)

	return &DynamicEndpointPolicy{
		targetUpstream: targetUpstream,
	}, nil
}

// Mode returns the processing mode for this policy.
func (p *DynamicEndpointPolicy) Mode() policyv1alpha2.ProcessingMode {
	return policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeProcess, // Need headers to process the request
		RequestBodyMode:    policyv1alpha2.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policyv1alpha2.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policyv1alpha2.BodyModeSkip,      // Don't need response body
	}
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
