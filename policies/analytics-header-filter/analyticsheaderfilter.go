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

package analyticsheaderfilter

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

var ins = &AnalyticsHeaderFilterPolicy{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// GetPolicyV2 delegates to GetPolicy.
func GetPolicyV2(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return GetPolicy(metadata, params)
}

func (p *AnalyticsHeaderFilterPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// AnalyticsHeaderFilterPolicy implements header exclusion from analytics
type AnalyticsHeaderFilterPolicy struct{}

// parseHeaderList parses a list of header names from parameters
func (p *AnalyticsHeaderFilterPolicy) parseHeaderList(headersRaw interface{}) []string {
	if headersRaw == nil {
		return nil
	}

	headers, ok := headersRaw.([]interface{})
	if !ok {
		return nil
	}

	headerList := make([]string, 0, len(headers))
	for _, headerRaw := range headers {
		header, ok := headerRaw.(string)
		if !ok || strings.TrimSpace(header) == "" {
			continue
		}
		// Normalize to lowercase for consistent matching
		headerList = append(headerList, strings.ToLower(strings.TrimSpace(header)))
	}

	return headerList
}

// parseMode parses and validates the mode parameter.
// Supported values are "allow" and "deny".
func (p *AnalyticsHeaderFilterPolicy) parseMode(modeRaw interface{}) (string, error) {
	if modeRaw == nil {
		return "", fmt.Errorf("mode is required")
	}

	mode, ok := modeRaw.(string)
	if !ok {
		return "", fmt.Errorf("'mode' must be a string")
	}

	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "allow" && mode != "deny" {
		return "", fmt.Errorf("'mode' must be either 'allow' or 'deny', got: %s", mode)
	}

	return mode, nil
}

// parseHeaderFilterConfig parses the header filter configuration object
// Expected structure: { "mode": "allow"|"deny", "headers": ["header1", "header2"] }.
func (p *AnalyticsHeaderFilterPolicy) parseHeaderFilterConfig(configRaw interface{}) (mode string, headers []string, err error) {
	if configRaw == nil {
		return "", nil, nil // No configuration provided
	}

	config, ok := configRaw.(map[string]interface{})
	if !ok {
		return "", nil, fmt.Errorf("header filter config must be an object")
	}

	// Parse mode (required)
	modeRaw, hasMode := config["mode"]
	if !hasMode || modeRaw == nil {
		return "", nil, fmt.Errorf("'mode' is required in header filter config")
	}
	mode, err = p.parseMode(modeRaw)
	if err != nil {
		return "", nil, err
	}

	// Parse headers (optional, defaults to empty array)
	headersRaw, _ := config["headers"]
	headers = p.parseHeaderList(headersRaw)

	return mode, headers, nil
}

// OnRequestHeaders processes request headers for analytics filtering in the header phase.
func (p *AnalyticsHeaderFilterPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	requestConfigRaw, hasRequestConfig := params["request"]
	if !hasRequestConfig || requestConfigRaw == nil {
		return policy.UpstreamRequestHeaderModifications{}
	}

	mode, specifiedHeaders, err := p.parseHeaderFilterConfig(requestConfigRaw)
	if err != nil {
		slog.Warn("Analytics Header Filter Policy: Failed to parse request headers filter config", "error", err)
		return policy.UpstreamRequestHeaderModifications{}
	}

	slog.Debug("Analytics Header Filter Policy: Parsed request config",
		"mode", mode,
		"headers", specifiedHeaders)

	return policy.UpstreamRequestHeaderModifications{
		AnalyticsHeaderFilter: policy.DropHeaderAction{
			Action:  mode,
			Headers: specifiedHeaders,
		},
	}
}

// OnResponseHeaders processes response headers for analytics filtering in the header phase.
func (p *AnalyticsHeaderFilterPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	responseConfigRaw, hasResponseConfig := params["response"]
	if !hasResponseConfig || responseConfigRaw == nil {
		return policy.DownstreamResponseHeaderModifications{}
	}

	mode, specifiedHeaders, err := p.parseHeaderFilterConfig(responseConfigRaw)
	if err != nil {
		slog.Warn("Analytics Header Filter Policy: Failed to parse response headers filter config", "error", err)
		return policy.DownstreamResponseHeaderModifications{}
	}

	return policy.DownstreamResponseHeaderModifications{
		AnalyticsHeaderFilter: policy.DropHeaderAction{
			Action:  mode,
			Headers: specifiedHeaders,
		},
	}
}
