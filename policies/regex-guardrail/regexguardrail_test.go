package regexguardrail

import (
	"encoding/json"
	"strings"
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestRegexGuardrailPolicy_Mode(t *testing.T) {
	p := &RegexGuardrailPolicy{}

	got := p.Mode()
	want := policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeSkip,
		RequestBodyMode:    policyv1alpha2.BodyModeBuffer,
		ResponseHeaderMode: policyv1alpha2.HeaderModeSkip,
		ResponseBodyMode:   policyv1alpha2.BodyModeStream,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestRegexGuardrailPolicy_GetPolicy_Defaults_RequestOnly(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	if !p.hasRequestParams {
		t.Fatalf("expected request params to be enabled")
	}
	if p.hasResponseParams {
		t.Fatalf("expected response params to be disabled")
	}
	if got := p.requestParams.JsonPath; got != DefaultRequestJSONPath {
		t.Fatalf("unexpected default jsonPath: got %q, want %q", got, DefaultRequestJSONPath)
	}
	if !p.requestParams.Enabled {
		t.Fatalf("expected request enabled by default")
	}
	if p.requestParams.Invert {
		t.Fatalf("expected default invert=false")
	}
	if p.requestParams.ShowAssessment {
		t.Fatalf("expected default showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_GetPolicy_Defaults_ResponseOnly(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex": "hello",
		},
	})

	if p.hasRequestParams {
		t.Fatalf("expected request params to be disabled")
	}
	if !p.hasResponseParams {
		t.Fatalf("expected response params to be enabled")
	}
	if got := p.responseParams.JsonPath; got != DefaultResponseJSONPath {
		t.Fatalf("unexpected default jsonPath: got %q, want %q", got, DefaultResponseJSONPath)
	}
	if p.responseParams.Enabled {
		t.Fatalf("expected response disabled by default")
	}
	if p.responseParams.Invert {
		t.Fatalf("expected default invert=false")
	}
	if p.responseParams.ShowAssessment {
		t.Fatalf("expected default showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_GetPolicy_RequestAndResponse(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "hello",
			"jsonPath":       "$.messages",
			"invert":         true,
			"showAssessment": true,
		},
		"response": map[string]interface{}{
			"regex":          "world",
			"jsonPath":       "$.output",
			"invert":         false,
			"showAssessment": true,
		},
	})

	if !p.hasRequestParams || !p.hasResponseParams {
		t.Fatalf("expected both request and response params enabled")
	}
	if p.requestParams.Regex != "hello" || p.responseParams.Regex != "world" {
		t.Fatalf("unexpected regex values: req=%q resp=%q", p.requestParams.Regex, p.responseParams.Regex)
	}
	if !p.requestParams.Enabled || p.responseParams.Enabled {
		t.Fatalf("unexpected enabled defaults: req=%v resp=%v", p.requestParams.Enabled, p.responseParams.Enabled)
	}
	if p.requestParams.JsonPath != "$.messages" || p.responseParams.JsonPath != "$.output" {
		t.Fatalf("unexpected jsonPath values: req=%q resp=%q", p.requestParams.JsonPath, p.responseParams.JsonPath)
	}
	if !p.requestParams.Invert || p.responseParams.Invert {
		t.Fatalf("unexpected invert values: req=%v resp=%v", p.requestParams.Invert, p.responseParams.Invert)
	}
	if !p.requestParams.ShowAssessment || !p.responseParams.ShowAssessment {
		t.Fatalf("expected showAssessment=true for both")
	}
}

func TestRegexGuardrailPolicy_GetPolicy_Errors(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name: "neither request nor response",
			params: map[string]interface{}{
				"foo": "bar",
			},
			wantErrContain: "at least one of 'request' or 'response' parameters must be provided",
		},
		{
			name: "request regex missing",
			params: map[string]interface{}{
				"request": map[string]interface{}{},
			},
			wantErrContain: "invalid request parameters: 'regex' parameter is required",
		},
		{
			name: "response regex wrong type",
			params: map[string]interface{}{
				"response": map[string]interface{}{
					"regex": 123,
				},
			},
			wantErrContain: "invalid response parameters: 'regex' must be a string",
		},
		{
			name: "regex empty",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex": "",
				},
			},
			wantErrContain: "invalid request parameters: 'regex' cannot be empty",
		},
		{
			name: "regex invalid pattern",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex": "[abc",
				},
			},
			wantErrContain: "invalid request parameters: invalid regex pattern",
		},
		{
			name: "jsonPath wrong type",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex":    "hello",
					"jsonPath": true,
				},
			},
			wantErrContain: "invalid request parameters: 'jsonPath' must be a string",
		},
		{
			name: "enabled wrong type",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex":   "hello",
					"enabled": "true",
				},
			},
			wantErrContain: "invalid request parameters: 'enabled' must be a boolean",
		},
		{
			name: "invert wrong type",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex":  "hello",
					"invert": "true",
				},
			},
			wantErrContain: "invalid request parameters: 'invert' must be a boolean",
		},
		{
			name: "showAssessment wrong type",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex":          "hello",
					"showAssessment": "true",
				},
			},
			wantErrContain: "invalid request parameters: 'showAssessment' must be a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestRegexGuardrailPolicy_ParseParams_DisabledFlow_DoesNotRequireRegex(t *testing.T) {
	tests := []struct {
		name            string
		defaultJSONPath string
		defaultEnabled  bool
	}{
		{
			name:            "request flow disabled",
			defaultJSONPath: DefaultRequestJSONPath,
			defaultEnabled:  RequestFlowEnabledByDefault,
		},
		{
			name:            "response flow disabled",
			defaultJSONPath: DefaultResponseJSONPath,
			defaultEnabled:  ResponseFlowEnabledByDefault,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(map[string]interface{}{"enabled": false}, tc.defaultJSONPath, tc.defaultEnabled)
			if err != nil {
				t.Fatalf("expected disabled flow params to parse without regex, got error: %v", err)
			}
			if got.Enabled {
				t.Fatalf("expected enabled=false, got true")
			}
		})
	}
}

func TestRegexGuardrailPolicy_DisabledFlow_GetPolicyAndHandlers_NoRequiredParams(t *testing.T) {
	t.Run("request flow disabled", func(t *testing.T) {
		pRaw, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, map[string]interface{}{
			"request": map[string]interface{}{"enabled": false},
		})
		if err != nil {
			t.Fatalf("expected disabled request flow without regex to be accepted, got %v", err)
		}
		p, ok := pRaw.(*RegexGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *RegexGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasRequestParams || p.requestParams.Enabled {
			t.Fatalf("expected request params present and disabled, got hasRequest=%v enabled=%v", p.hasRequestParams, p.requestParams.Enabled)
		}

		action := p.OnRequestBody(newRequestContextWithBody(`{"messages":[{"content":"hello"}]}`), nil)
		if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
			t.Fatalf("expected request no-op when request.enabled=false, got %T", action)
		}
	})

	t.Run("response flow disabled", func(t *testing.T) {
		pRaw, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, map[string]interface{}{
			"response": map[string]interface{}{"enabled": false},
		})
		if err != nil {
			t.Fatalf("expected disabled response flow without regex to be accepted, got %v", err)
		}
		p, ok := pRaw.(*RegexGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *RegexGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasResponseParams || p.responseParams.Enabled {
			t.Fatalf("expected response params present and disabled, got hasResponse=%v enabled=%v", p.hasResponseParams, p.responseParams.Enabled)
		}

		action := p.OnResponseBody(newResponseContextWithBody(`{"status":"ok"}`), nil)
		if _, ok := action.(policyv1alpha2.DownstreamResponseModifications); !ok {
			t.Fatalf("expected response no-op when response.enabled=false, got %T", action)
		}
	})
}

func TestRegexGuardrailPolicy_OnRequestBody_NoRequestConfig_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex": "hello",
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"message":"hello"}`), nil)
	if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_Disabled_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":   "hello",
			"enabled": false,
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"messages":[{"content":"hello"}]}`), nil)
	if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnResponseBody_NoResponseConfig_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	action := p.OnResponseBody(newResponseContextWithBody(`{"message":"hello"}`), nil)
	if _, ok := action.(policyv1alpha2.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnResponseBody_Disabled_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex":   "hello",
			"enabled": false,
		},
	})

	action := p.OnResponseBody(newResponseContextWithBody(`{"message":"hello"}`), nil)
	if _, ok := action.(policyv1alpha2.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_EmptyBody_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	ctx := &policyv1alpha2.RequestContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "test-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policyv1alpha2.Body{
			Content: []byte{},
			Present: false,
		},
	}
	action := p.OnRequestBody(ctx, nil)
	if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnResponseBody_EmptyBody_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex": "hello",
		},
	})

	ctx := &policyv1alpha2.ResponseContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "test-id",
			Metadata:  map[string]interface{}{},
		},
		ResponseBody: &policyv1alpha2.Body{
			Content: []byte{},
			Present: false,
		},
	}
	action := p.OnResponseBody(ctx, nil)
	if _, ok := action.(policyv1alpha2.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_DefaultJSONPath_Success(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"messages":[{"content":"hello world"}]}`), nil)
	if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_CustomJSONPath_Success(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "secret",
			"jsonPath": "$.messages[0].content",
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"messages":[{"content":"my secret token"}]}`), nil)
	if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_EmptyJSONPath_UsesWholePayload(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "sam",
			"jsonPath": "",
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"name":"sam"}`), nil)
	if _, ok := action.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_InvertBehavior(t *testing.T) {
	passPolicy := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "forbidden",
			"jsonPath": "$.messages",
			"invert":   true,
		},
	})
	passAction := passPolicy.OnRequestBody(newRequestContextWithBody(`{"messages":"allowed content"}`), nil)
	if _, ok := passAction.(policyv1alpha2.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass with invert=true on non-match, got %T", passAction)
	}

	failPolicy := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "forbidden",
			"jsonPath": "$.messages",
			"invert":   true,
		},
	})
	failAction := failPolicy.OnRequestBody(newRequestContextWithBody(`{"messages":"contains forbidden term"}`), nil)
	assertRequestErrorResponse(t, failAction, false, "REQUEST")
}

func TestRegexGuardrailPolicy_OnRequestBody_RegexViolation_ShowAssessmentFalse(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "abc",
			"jsonPath":       "$.messages",
			"showAssessment": false,
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"messages":"does not match"}`), nil)
	body := assertRequestErrorResponse(t, action, false, "REQUEST")

	message := extractMessageAssessment(t, body)
	if _, exists := message["assessments"]; exists {
		t.Fatalf("did not expect assessments when showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_RegexViolation_ShowAssessmentTrue(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "abc",
			"jsonPath":       "$.messages",
			"showAssessment": true,
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"messages":"does not match"}`), nil)
	body := assertRequestErrorResponse(t, action, true, "REQUEST")

	message := extractMessageAssessment(t, body)
	assessments, ok := message["assessments"].(string)
	if !ok || !strings.Contains(assessments, "Violation of regular expression detected") {
		t.Fatalf("expected detailed assessments for violation, got %v", message["assessments"])
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_ExtractionError_ShowAssessmentTrue(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "abc",
			"jsonPath":       "$.missing.path",
			"showAssessment": true,
		},
	})

	action := p.OnRequestBody(newRequestContextWithBody(`{"message":"abc"}`), nil)
	body := assertRequestErrorResponse(t, action, true, "REQUEST")
	message := extractMessageAssessment(t, body)

	assessments, ok := message["assessments"].(string)
	if !ok || !strings.Contains(assessments, "key not found") {
		t.Fatalf("expected extraction error details in assessments, got %v", message["assessments"])
	}
}

func TestRegexGuardrailPolicy_OnRequestBody_DefaultJSONPath_ArrayPayload_ExtractionError(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	// Default jsonPath is $.messages[-1].content; this payload has messages as a string,
	// so indexed extraction fails.
	action := p.OnRequestBody(newRequestContextWithBody(`{"messages":"hello"}`), nil)
	assertRequestErrorResponse(t, action, false, "REQUEST")
}

func TestRegexGuardrailPolicy_OnResponseBody_Success(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"enabled":  true,
			"regex":    "ok",
			"jsonPath": "$.status",
		},
	})

	action := p.OnResponseBody(newResponseContextWithBody(`{"status":"ok"}`), nil)
	if _, ok := action.(policyv1alpha2.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnResponseBody_RegexViolation_ShowAssessmentFalse(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"enabled":        true,
			"regex":          "ok",
			"jsonPath":       "$.status",
			"showAssessment": false,
		},
	})

	action := p.OnResponseBody(newResponseContextWithBody(`{"status":"failed"}`), nil)
	body := assertResponseErrorResponse(t, action, false, "RESPONSE")
	message := extractMessageAssessment(t, body)
	if _, exists := message["assessments"]; exists {
		t.Fatalf("did not expect assessments when showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_OnResponseBody_RegexViolation_ShowAssessmentTrue(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"enabled":        true,
			"regex":          "ok",
			"jsonPath":       "$.status",
			"showAssessment": true,
		},
	})

	action := p.OnResponseBody(newResponseContextWithBody(`{"status":"failed"}`), nil)
	body := assertResponseErrorResponse(t, action, true, "RESPONSE")
	message := extractMessageAssessment(t, body)
	if _, exists := message["assessments"]; !exists {
		t.Fatalf("expected assessments when showAssessment=true")
	}
}

func TestRegexGuardrailPolicy_BuildAssessmentObject(t *testing.T) {
	p := &RegexGuardrailPolicy{}

	req := p.buildAssessmentObject("reason", nil, false, false)
	if got := req["direction"]; got != "REQUEST" {
		t.Fatalf("unexpected request direction: %v", got)
	}
	if got := req["actionReason"]; got != "Violation of regular expression detected." {
		t.Fatalf("unexpected request actionReason: %v", got)
	}

	respWithErr := p.buildAssessmentObject("Error extracting value from JSONPath", errSentinel("boom"), true, true)
	if got := respWithErr["direction"]; got != "RESPONSE" {
		t.Fatalf("unexpected response direction: %v", got)
	}
	if got := respWithErr["actionReason"]; got != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected response actionReason: %v", got)
	}
	if got := respWithErr["assessments"]; got != "boom" {
		t.Fatalf("unexpected response assessments: %v", got)
	}
}

func mustGetRegexPolicy(t *testing.T, params map[string]interface{}) *RegexGuardrailPolicy {
	t.Helper()

	p, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	rp, ok := p.(*RegexGuardrailPolicy)
	if !ok {
		t.Fatalf("expected *RegexGuardrailPolicy, got %T", p)
	}
	return rp
}

func assertRequestErrorResponse(t *testing.T, action policyv1alpha2.RequestAction, expectAssessments bool, wantDirection string) map[string]interface{} {
	t.Helper()

	resp, ok := action.(policyv1alpha2.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("unexpected status code: got %d, want %d", resp.StatusCode, GuardrailErrorCode)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Fatalf("unexpected content type header: %v", resp.Headers["Content-Type"])
	}

	body := decodeJSONMap(t, resp.Body)
	if got := body["type"]; got != "REGEX_GUARDRAIL" {
		t.Fatalf("unexpected type: %v", got)
	}
	assessment := extractMessageAssessment(t, body)
	validateAssessmentCore(t, assessment, expectAssessments, wantDirection)
	return body
}

func assertResponseErrorResponse(t *testing.T, action policyv1alpha2.ResponseAction, expectAssessments bool, wantDirection string) map[string]interface{} {
	t.Helper()

	resp, ok := action.(policyv1alpha2.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("unexpected status code: got %v, want %d", resp.StatusCode, GuardrailErrorCode)
	}
	if resp.DownstreamResponseHeaderModifications.HeadersToSet["Content-Type"] != "application/json" {
		t.Fatalf("unexpected content type header: %v", resp.DownstreamResponseHeaderModifications.HeadersToSet["Content-Type"])
	}

	body := decodeJSONMap(t, resp.Body)
	if got := body["type"]; got != "REGEX_GUARDRAIL" {
		t.Fatalf("unexpected type: %v", got)
	}
	assessment := extractMessageAssessment(t, body)
	validateAssessmentCore(t, assessment, expectAssessments, wantDirection)
	return body
}

func validateAssessmentCore(t *testing.T, assessment map[string]interface{}, expectAssessments bool, wantDirection string) {
	t.Helper()

	if got := assessment["action"]; got != "GUARDRAIL_INTERVENED" {
		t.Fatalf("unexpected action: %v", got)
	}
	if got := assessment["interveningGuardrail"]; got != "regex-guardrail" {
		t.Fatalf("unexpected interveningGuardrail: %v", got)
	}
	if got := assessment["direction"]; got != wantDirection {
		t.Fatalf("unexpected direction: got %v, want %q", got, wantDirection)
	}
	if expectAssessments {
		if _, exists := assessment["assessments"]; !exists {
			t.Fatalf("expected assessments to be present")
		}
	}
}

func extractMessageAssessment(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()

	msg, ok := body["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected body.message as object, got %T", body["message"])
	}
	return msg
}

func decodeJSONMap(t *testing.T, payload []byte) map[string]interface{} {
	t.Helper()

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("failed to unmarshal JSON body: %v; body=%s", err, string(payload))
	}
	return result
}

func newRequestContextWithBody(body string) *policyv1alpha2.RequestContext {
	return &policyv1alpha2.RequestContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "test-request-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policyv1alpha2.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func newResponseContextWithBody(body string) *policyv1alpha2.ResponseContext {
	return &policyv1alpha2.ResponseContext{
		SharedContext: &policyv1alpha2.SharedContext{
			RequestID: "test-request-id",
			Metadata:  map[string]interface{}{},
		},
		ResponseBody: &policyv1alpha2.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

type errSentinel string

func (e errSentinel) Error() string {
	return string(e)
}
