// Package dynamicendpoint provides a policy for dynamic upstream routing.
// It demonstrates the UpstreamName functionality in the SDK.
package dynamicendpoint

import (
	"log/slog"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policyv1alpha "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// DynamicEndpointPolicy routes requests to a dynamically specified upstream.
type DynamicEndpointPolicy struct {
	targetUpstream string
}

// GetPolicy creates a new instance of the dynamic endpoint policyv1alpha.
func GetPolicy(
	metadata policyv1alpha.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha.Policy, error) {
	slog.Debug("[Dynamic Endpoint]: GetPolicy called")

	targetUpstream, _ := params["targetUpstream"].(string)

	return &DynamicEndpointPolicy{
		targetUpstream: targetUpstream,
	}, nil
}

// Mode returns the processing mode for this policyv1alpha.
func (p *DynamicEndpointPolicy) Mode() policyv1alpha.ProcessingMode {
	return policyv1alpha.ProcessingMode{
		RequestHeaderMode:  policyv1alpha.HeaderModeProcess, // Need headers to process the request
		RequestBodyMode:    policyv1alpha.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policyv1alpha.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policyv1alpha.BodyModeSkip,      // Don't need response body
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

// OnRequest applies upstream routing for v1alpha engine compatibility.
func (p *DynamicEndpointPolicy) OnRequest(ctx *policyv1alpha.RequestContext, params map[string]interface{}) policyv1alpha.RequestAction {
	slog.Info("[Dynamic Endpoint]: OnRequest called", "targetUpstream", p.targetUpstream)

	if p.targetUpstream == "" {
		slog.Warn("[Dynamic Endpoint]: No target upstream configured, passing through")
		return policyv1alpha.UpstreamRequestModifications{}
	}

	// Use UpstreamName to route the request to the target upstream definition.
	// The upstream name must match an entry in the API's upstreamDefinitions.
	return policyv1alpha.UpstreamRequestModifications{
		UpstreamName: &p.targetUpstream,
	}
}

// OnResponse is not used by this policyv1alpha.
func (p *DynamicEndpointPolicy) OnResponse(ctx *policyv1alpha.ResponseContext, params map[string]interface{}) policyv1alpha.ResponseAction {
	return policyv1alpha.UpstreamResponseModifications{}
}
