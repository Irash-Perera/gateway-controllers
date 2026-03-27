package contentlengthguardrail

import (
	"encoding/json"
	"strings"
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func mustMessageMap(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}

	msg, ok := payload["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected message object, got %#v", payload["message"])
	}

	return msg
}

func TestExtractInt(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		expected  int
		expectErr bool
	}{
		{"int", 10, 10, false},
		{"int64", int64(11), 11, false},
		{"float64 integer", float64(12), 12, false},
		{"string integer", "13", 13, false},
		{"string float integer", "14.0", 14, false},
		{"float64 non-integer", float64(10.5), 0, true},
		{"string non-integer", "10.5", 0, true},
		{"invalid string", "abc", 0, true},
		{"bool", true, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractInt(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, got)
			}
		})
	}
}

func TestParseParams(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]interface{}
		expectErr   bool
		errContains string
		expected    ContentLengthGuardrailPolicyParams
	}{
		{
			name:        "missing min",
			input:       map[string]interface{}{"max": 10},
			expectErr:   true,
			errContains: "'min' parameter is required",
		},
		{
			name:        "missing max",
			input:       map[string]interface{}{"min": 1},
			expectErr:   true,
			errContains: "'max' parameter is required",
		},
		{
			name:        "negative min",
			input:       map[string]interface{}{"min": -1, "max": 10},
			expectErr:   true,
			errContains: "'min' cannot be negative",
		},
		{
			name:        "max not greater than zero",
			input:       map[string]interface{}{"min": 0, "max": 0},
			expectErr:   true,
			errContains: "'max' must be greater than 0",
		},
		{
			name:        "min greater than max",
			input:       map[string]interface{}{"min": 11, "max": 10},
			expectErr:   true,
			errContains: "'min' cannot be greater than 'max'",
		},
		{
			name:        "invalid jsonPath type",
			input:       map[string]interface{}{"min": 1, "max": 10, "jsonPath": 12},
			expectErr:   true,
			errContains: "'jsonPath' must be a string",
		},
		{
			name:        "invalid enabled type",
			input:       map[string]interface{}{"min": 1, "max": 10, "enabled": "true"},
			expectErr:   true,
			errContains: "'enabled' must be a boolean",
		},
		{
			name:        "invalid invert type",
			input:       map[string]interface{}{"min": 1, "max": 10, "invert": "true"},
			expectErr:   true,
			errContains: "'invert' must be a boolean",
		},
		{
			name:        "invalid showAssessment type",
			input:       map[string]interface{}{"min": 1, "max": 10, "showAssessment": "true"},
			expectErr:   true,
			errContains: "'showAssessment' must be a boolean",
		},
		{
			name: "valid with defaults",
			input: map[string]interface{}{
				"min": 1,
				"max": 10,
			},
			expected: ContentLengthGuardrailPolicyParams{
				Enabled:          RequestFlowEnabledByDefault,
				Min:              1,
				Max:              10,
				JsonPath:         DefaultJSONPath,
				StreamingJsonPath: DefaultStreamingJsonPath,
			},
		},
		{
			name: "valid with all optional fields",
			input: map[string]interface{}{
				"min":            "2",
				"max":            float64(20),
				"jsonPath":       "$.text",
				"invert":         true,
				"showAssessment": true,
			},
			expected: ContentLengthGuardrailPolicyParams{
				Enabled:          RequestFlowEnabledByDefault,
				Min:              2,
				Max:              20,
				JsonPath:         "$.text",
				StreamingJsonPath: DefaultStreamingJsonPath,
				Invert:           true,
				ShowAssessment:   true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(tc.input, false)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("expected %+v, got %+v", tc.expected, got)
			}
		})
	}

	responseDefaults, err := parseParams(map[string]interface{}{"min": 1, "max": 10}, true)
	if err != nil {
		t.Fatalf("unexpected response defaults parse error: %v", err)
	}
	if responseDefaults.JsonPath != DefaultResponseJSONPath {
		t.Fatalf("expected response default jsonPath %q, got %q", DefaultResponseJSONPath, responseDefaults.JsonPath)
	}
	if responseDefaults.Enabled != ResponseFlowEnabledByDefault {
		t.Fatalf("expected response default enabled %v, got %v", ResponseFlowEnabledByDefault, responseDefaults.Enabled)
	}
}

func TestParseParams_DisabledFlow_DoesNotRequireMinMax(t *testing.T) {
	tests := []struct {
		name       string
		isResponse bool
	}{
		{
			name:       "request flow disabled",
			isResponse: false,
		},
		{
			name:       "response flow disabled",
			isResponse: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(map[string]interface{}{"enabled": false}, tc.isResponse)
			if err != nil {
				t.Fatalf("expected disabled flow params to parse without min/max, got error: %v", err)
			}
			if got.Enabled {
				t.Fatalf("expected enabled=false, got true")
			}
		})
	}
}

func TestDisabledFlow_GetPolicyAndHandlers_NoRequiredParams(t *testing.T) {
	t.Run("request flow disabled", func(t *testing.T) {
		pRaw, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, map[string]interface{}{
			"request": map[string]interface{}{"enabled": false},
		})
		if err != nil {
			t.Fatalf("expected disabled request flow without min/max to be accepted, got %v", err)
		}
		p, ok := pRaw.(*ContentLengthGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *ContentLengthGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasRequestParams || p.requestParams.Enabled {
			t.Fatalf("expected request params present and disabled, got hasRequest=%v enabled=%v", p.hasRequestParams, p.requestParams.Enabled)
		}

		action := p.OnRequestBody(&policyv1alpha2.RequestContext{
			Body: &policyv1alpha2.Body{Content: []byte(`{"messages":[{"content":"hello"}]}`)},
		}, nil)
		if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
			t.Fatalf("expected request no-op when request.enabled=false, got %T", action)
		}
	})

	t.Run("response flow disabled", func(t *testing.T) {
		pRaw, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, map[string]interface{}{
			"response": map[string]interface{}{"enabled": false},
		})
		if err != nil {
			t.Fatalf("expected disabled response flow without min/max to be accepted, got %v", err)
		}
		p, ok := pRaw.(*ContentLengthGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *ContentLengthGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasResponseParams || p.responseParams.Enabled {
			t.Fatalf("expected response params present and disabled, got hasResponse=%v enabled=%v", p.hasResponseParams, p.responseParams.Enabled)
		}

		action := p.OnResponseBody(&policyv1alpha2.ResponseContext{
			ResponseBody: &policyv1alpha2.Body{Content: []byte(`{"choices":[{"message":{"content":"hello"}}]}`)},
		}, nil)
		if _, ok := action.(policyv1alpha2.DownstreamResponseModifications); !ok {
			t.Fatalf("expected response no-op when response.enabled=false, got %T", action)
		}
	})
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		expectErr   bool
		errContains string
		check       func(t *testing.T, p *ContentLengthGuardrailPolicy)
	}{
		{
			name:        "missing request and response",
			params:      map[string]interface{}{},
			expectErr:   true,
			errContains: "at least one of 'request' or 'response' parameters must be provided",
		},
		{
			name: "invalid request params",
			params: map[string]interface{}{
				"request": map[string]interface{}{"min": -1, "max": 10},
			},
			expectErr:   true,
			errContains: "invalid request parameters",
		},
		{
			name: "invalid response params",
			params: map[string]interface{}{
				"response": map[string]interface{}{"min": -1, "max": 10},
			},
			expectErr:   true,
			errContains: "invalid response parameters",
		},
		{
			name: "request only",
			params: map[string]interface{}{
				"request": map[string]interface{}{"min": 1, "max": 10},
			},
			check: func(t *testing.T, p *ContentLengthGuardrailPolicy) {
				if !p.hasRequestParams || p.hasResponseParams {
					t.Fatalf("expected request=true response=false, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
				}
				if p.requestParams.Min != 1 || p.requestParams.Max != 10 {
					t.Fatalf("unexpected request params: %+v", p.requestParams)
				}
				if p.requestParams.JsonPath != DefaultJSONPath {
					t.Fatalf("expected default request jsonPath %q, got %q", DefaultJSONPath, p.requestParams.JsonPath)
				}
				if !p.requestParams.Enabled {
					t.Fatalf("expected request enabled by default")
				}
			},
		},
		{
			name: "response only",
			params: map[string]interface{}{
				"response": map[string]interface{}{"min": 2, "max": 20},
			},
			check: func(t *testing.T, p *ContentLengthGuardrailPolicy) {
				if p.hasRequestParams || !p.hasResponseParams {
					t.Fatalf("expected request=false response=true, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
				}
				if p.responseParams.Min != 2 || p.responseParams.Max != 20 {
					t.Fatalf("unexpected response params: %+v", p.responseParams)
				}
				if p.responseParams.JsonPath != DefaultResponseJSONPath {
					t.Fatalf("expected default response jsonPath %q, got %q", DefaultResponseJSONPath, p.responseParams.JsonPath)
				}
				if p.responseParams.Enabled {
					t.Fatalf("expected response disabled by default")
				}
			},
		},
		{
			name: "both request and response",
			params: map[string]interface{}{
				"request":  map[string]interface{}{"min": 1, "max": 10},
				"response": map[string]interface{}{"min": 2, "max": 20},
			},
			check: func(t *testing.T, p *ContentLengthGuardrailPolicy) {
				if !p.hasRequestParams || !p.hasResponseParams {
					t.Fatalf("expected both request and response params to be present")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pRaw, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, tc.params)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			p, ok := pRaw.(*ContentLengthGuardrailPolicy)
			if !ok {
				t.Fatalf("expected *ContentLengthGuardrailPolicy, got %T", pRaw)
			}

			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

func TestMode(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}
	mode := p.Mode()

	if mode.RequestHeaderMode != policyv1alpha2.HeaderModeSkip {
		t.Fatalf("expected RequestHeaderMode=Skip, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policyv1alpha2.BodyModeBuffer {
		t.Fatalf("expected RequestBodyMode=Buffer, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policyv1alpha2.HeaderModeSkip {
		t.Fatalf("expected ResponseHeaderMode=Skip, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policyv1alpha2.BodyModeStream {
		t.Fatalf("expected ResponseBodyMode=Buffer, got %v", mode.ResponseBodyMode)
	}
}

func TestValidatePayload_RequestPaths(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	pass := p.validatePayloadV2([]byte("hello"), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10}, false)
	if _, ok := pass.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on valid payload, got %T", pass)
	}

	fail := p.validatePayloadV2([]byte(""), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10, ShowAssessment: true}, false)
	imm, ok := fail.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on invalid payload, got %T", fail)
	}
	if imm.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
	}
	msg := mustMessageMap(t, imm.Body)
	if msg["direction"] != "REQUEST" {
		t.Fatalf("expected REQUEST direction, got %#v", msg["direction"])
	}
	if msg["interveningGuardrail"] != "content-length-guardrail" {
		t.Fatalf("unexpected interveningGuardrail: %#v", msg["interveningGuardrail"])
	}
	if msg["assessments"] == nil {
		t.Fatalf("expected assessments when showAssessment is true")
	}
}

func TestValidatePayload_ResponsePaths(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	pass := p.validatePayloadV2([]byte("hello"), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10}, true)
	if _, ok := pass.(policyv1alpha2.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications on valid response payload, got %T", pass)
	}

	fail := p.validatePayloadV2([]byte(""), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10, ShowAssessment: false}, true)
	resp, ok := fail.(policyv1alpha2.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications on invalid response payload, got %T", fail)
	}
	if resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected response status %d, got %#v", GuardrailErrorCode, resp.StatusCode)
	}
	if resp.DownstreamResponseHeaderModifications.HeadersToSet["Content-Type"] != "application/json" {
		t.Fatalf("expected response content-type header, got %#v", resp.DownstreamResponseHeaderModifications.HeadersToSet)
	}
	msg := mustMessageMap(t, resp.Body)
	if msg["direction"] != "RESPONSE" {
		t.Fatalf("expected RESPONSE direction, got %#v", msg["direction"])
	}
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("did not expect assessments when showAssessment is false")
	}
}

func TestValidatePayload_InvertMode(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}
	params := ContentLengthGuardrailPolicyParams{
		Min:    1,
		Max:    3,
		Invert: true,
	}

	// In invert mode, content within range should fail.
	within := p.validatePayloadV2([]byte("ab"), params, false)
	if _, ok := within.(policyv1alpha2.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse when in-range payload is rejected in invert mode, got %T", within)
	}

	// In invert mode, content outside range should pass.
	outside := p.validatePayloadV2([]byte("abcd"), params, false)
	if _, ok := outside.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications when out-of-range payload passes in invert mode, got %T", outside)
	}
}

func TestValidatePayload_JSONPathExtraction(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}
	payload := []byte(`{"data":{"text":"abc"}}`)

	pass := p.validatePayloadV2(payload, ContentLengthGuardrailPolicyParams{
		Min:      3,
		Max:      3,
		JsonPath: "$.data.text",
	}, false)
	if _, ok := pass.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass using jsonPath extraction, got %T", pass)
	}

	fail := p.validatePayloadV2(payload, ContentLengthGuardrailPolicyParams{
		Min:            1,
		Max:            10,
		JsonPath:       "$.missing",
		ShowAssessment: true,
	}, false)
	imm, ok := fail.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on jsonPath extraction failure, got %T", fail)
	}
	msg := mustMessageMap(t, imm.Body)
	if msg["actionReason"] != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected actionReason: %#v", msg["actionReason"])
	}
	assessmentStr, ok := msg["assessments"].(string)
	if !ok || assessmentStr == "" {
		t.Fatalf("expected string assessments from extraction error, got %#v", msg["assessments"])
	}
}

func TestBuildAssessmentObject(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	normal := p.buildAssessmentObject("content length 20 bytes is outside the allowed range 1-10 bytes", nil, false, true, 1, 10)
	if normal["actionReason"] != "Violation of applied content length constraints detected." {
		t.Fatalf("unexpected actionReason: %#v", normal["actionReason"])
	}
	if normal["assessments"] != "Violation of content length detected. Expected content length to be between 1 and 10 bytes." {
		t.Fatalf("unexpected assessments: %#v", normal["assessments"])
	}

	inverted := p.buildAssessmentObject("content length 2 bytes is within the excluded range 1-10 bytes", nil, false, true, 1, 10)
	if inverted["assessments"] != "Violation of content length detected. Expected content length to be outside the range of 1 to 10 bytes." {
		t.Fatalf("unexpected inverted assessments: %#v", inverted["assessments"])
	}

	withErr := p.buildAssessmentObject("Error extracting value from JSONPath", json.Unmarshal([]byte("{"), &map[string]interface{}{}), false, true, 1, 10)
	if withErr["actionReason"] != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected actionReason with error: %#v", withErr["actionReason"])
	}
	if _, ok := withErr["assessments"].(string); !ok {
		t.Fatalf("expected error assessments string, got %#v", withErr["assessments"])
	}
}

func TestOnRequestBodyAndOnResponseBody(t *testing.T) {
	// No request params configured -> no-op.
	p := &ContentLengthGuardrailPolicy{hasRequestParams: false, hasResponseParams: false}
	reqNoOp := p.OnRequestBody(&policyv1alpha2.RequestContext{}, nil)
	if _, ok := reqNoOp.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op modifications, got %T", reqNoOp)
	}
	respNoOp := p.OnResponseBody(&policyv1alpha2.ResponseContext{}, nil)
	if _, ok := respNoOp.(policyv1alpha2.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op modifications, got %T", respNoOp)
	}

	// Request validation with nil body should fail when min > 0.
	p.hasRequestParams = true
	p.requestParams = ContentLengthGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10}
	reqFail := p.OnRequestBody(&policyv1alpha2.RequestContext{Body: nil}, nil)
	if _, ok := reqFail.(policyv1alpha2.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse for request nil-body validation failure, got %T", reqFail)
	}

	// Response validation with nil body should fail when min > 0.
	p.hasResponseParams = true
	p.responseParams = ContentLengthGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10}
	respFail := p.OnResponseBody(&policyv1alpha2.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respFail.(policyv1alpha2.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications for response nil-body validation failure, got %T", respFail)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status code %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	// Explicitly disabled request flow should no-op.
	p.requestParams.Enabled = false
	reqDisabled := p.OnRequestBody(&policyv1alpha2.RequestContext{Body: &policyv1alpha2.Body{Content: []byte(`{"messages":[{"content":"hi"}]}`)}}, nil)
	if _, ok := reqDisabled.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	// Explicitly disabled response flow should no-op.
	p.responseParams.Enabled = false
	respDisabled := p.OnResponseBody(&policyv1alpha2.ResponseContext{ResponseBody: &policyv1alpha2.Body{Content: []byte(`{"choices":[{"message":{"content":"hi"}}]}`)}}, nil)
	if _, ok := respDisabled.(policyv1alpha2.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}
