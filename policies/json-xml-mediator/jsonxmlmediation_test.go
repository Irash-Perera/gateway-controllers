package jsonxmlmediation

import (
	"encoding/json"
	"strings"
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func createHeaders(key, value string) *policyv1alpha2.Headers {
	h := map[string][]string{}
	h[key] = []string{value}
	return policyv1alpha2.NewHeaders(h)
}

func parseErrorJSON(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	return out
}

func newConfiguredPolicy(t *testing.T, params map[string]interface{}) *JSONXMLMediationPolicy {
	t.Helper()

	p, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	typed, ok := p.(*JSONXMLMediationPolicy)
	if !ok {
		t.Fatalf("expected *JSONXMLMediationPolicy, got %T", p)
	}

	return typed
}

func configuredParams(upstreamPayloadFormat string, downstreamPayloadFormat ...string) map[string]interface{} {
	params := map[string]interface{}{
		"upstreamPayloadFormat": upstreamPayloadFormat,
	}
	if len(downstreamPayloadFormat) > 0 {
		params["downsteamPayloadFormat"] = downstreamPayloadFormat[0]
	}
	return params
}

func TestGetPolicy(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams(" XML ", " json "))
	if p.upstreamPayloadFormat != upstreamPayloadFormatXML {
		t.Fatalf("expected normalized upstream format %q, got %q", upstreamPayloadFormatXML, p.upstreamPayloadFormat)
	}
	if p.downstreamPayloadFormat != upstreamPayloadFormatJSON {
		t.Fatalf("expected downstream format %q, got %q", upstreamPayloadFormatJSON, p.downstreamPayloadFormat)
	}

	p2 := newConfiguredPolicy(t, configuredParams("json", " xml "))
	if p2.upstreamPayloadFormat != upstreamPayloadFormatJSON {
		t.Fatalf("expected upstream format %q, got %q", upstreamPayloadFormatJSON, p2.upstreamPayloadFormat)
	}
	if p2.downstreamPayloadFormat != upstreamPayloadFormatXML {
		t.Fatalf("expected normalized downstream format %q, got %q", upstreamPayloadFormatXML, p2.downstreamPayloadFormat)
	}

	if p == p2 {
		t.Fatalf("expected distinct policy instances per configuration")
	}
}

func TestGetPolicy_InvalidUpstreamFormatConfig(t *testing.T) {
	cases := []struct {
		name      string
		params    map[string]interface{}
		expectMsg string
	}{
		{
			name:      "nil params",
			params:    nil,
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "missing upstreamPayloadFormat",
			params:    map[string]interface{}{},
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "empty upstreamPayloadFormat",
			params:    map[string]interface{}{"upstreamPayloadFormat": ""},
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "invalid enum value",
			params:    map[string]interface{}{"upstreamPayloadFormat": "yaml"},
			expectMsg: "upstreamPayloadFormat must be one of [xml, json]",
		},
		{
			name:      "invalid type",
			params:    map[string]interface{}{"upstreamPayloadFormat": true},
			expectMsg: "upstreamPayloadFormat must be a non-empty string",
		},
		{
			name:      "missing downstreamPayloadFormat",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml"},
			expectMsg: "downsteamPayloadFormat must be a non-empty string",
		},
		{
			name:      "empty downstreamPayloadFormat",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downsteamPayloadFormat": ""},
			expectMsg: "downsteamPayloadFormat must be a non-empty string",
		},
		{
			name:      "invalid downstream enum value",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downsteamPayloadFormat": "yaml"},
			expectMsg: "downsteamPayloadFormat must be one of [xml, json]",
		},
		{
			name:      "same upstream and downstream format",
			params:    map[string]interface{}{"upstreamPayloadFormat": "xml", "downsteamPayloadFormat": "xml"},
			expectMsg: "downsteamPayloadFormat must be different from upstreamPayloadFormat",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetPolicyV2(policyv1alpha2.PolicyMetadata{}, tc.params)
			if err == nil {
				t.Fatalf("expected error for params %#v", tc.params)
			}
			if !strings.Contains(err.Error(), tc.expectMsg) {
				t.Fatalf("expected error containing %q, got %q", tc.expectMsg, err.Error())
			}
		})
	}
}

func TestMode(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))
	mode := p.Mode()
	expected := policyv1alpha2.ProcessingMode{
		RequestHeaderMode:  policyv1alpha2.HeaderModeProcess,
		RequestBodyMode:    policyv1alpha2.BodyModeBuffer,
		ResponseHeaderMode: policyv1alpha2.HeaderModeProcess,
		ResponseBodyMode:   policyv1alpha2.BodyModeBuffer,
	}
	if mode != expected {
		t.Fatalf("unexpected mode: %+v", mode)
	}
}

func TestOnRequest_JSONToXML_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))
	ctx := &policyv1alpha2.RequestContext{
		Body:    &policyv1alpha2.Body{Content: []byte(`{"name":"John","age":30}`), Present: true},
		Headers: createHeaders("content-type", "application/json"),
	}

	result := p.OnRequestBody(ctx, nil)
	mods, ok := result.(policyv1alpha2.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
	if mods.Body == nil || !strings.Contains(string(mods.Body), "<name>John</name>") {
		t.Fatalf("expected transformed XML body, got: %s", string(mods.Body))
	}
	if mods.UpstreamRequestHeaderModifications.HeadersToSet["content-type"] != "application/xml" {
		t.Fatalf("unexpected content-type: %s", mods.UpstreamRequestHeaderModifications.HeadersToSet["content-type"])
	}
	if mods.UpstreamRequestHeaderModifications.HeadersToSet["content-length"] == "" {
		t.Fatalf("expected content-length header")
	}
}

func TestOnRequest_XMLToJSON_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("json", "xml"))
	ctx := &policyv1alpha2.RequestContext{
		Body:    &policyv1alpha2.Body{Content: []byte(`<root><name>John</name><age>30</age></root>`), Present: true},
		Headers: createHeaders("content-type", "text/xml; charset=utf-8"),
	}

	result := p.OnRequestBody(ctx, nil)
	mods, ok := result.(policyv1alpha2.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
	if mods.Body == nil {
		t.Fatalf("expected transformed JSON body")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(mods.Body, &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v", err)
	}
	if mods.UpstreamRequestHeaderModifications.HeadersToSet["content-type"] != "application/json" {
		t.Fatalf("unexpected content-type: %s", mods.UpstreamRequestHeaderModifications.HeadersToSet["content-type"])
	}
}

func TestOnResponse_XMLToJSON_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))
	ctx := &policyv1alpha2.ResponseContext{
		ResponseBody:    &policyv1alpha2.Body{Content: []byte(`<root><status>ok</status></root>`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/xml"),
	}

	result := p.OnResponseBody(ctx, nil)
	mods, ok := result.(policyv1alpha2.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mods.Body == nil {
		t.Fatalf("expected transformed JSON response body")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(mods.Body, &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v", err)
	}
	if mods.DownstreamResponseHeaderModifications.HeadersToSet["content-type"] != "application/json" {
		t.Fatalf("unexpected content-type: %s", mods.DownstreamResponseHeaderModifications.HeadersToSet["content-type"])
	}
}

func TestOnResponse_JSONToXML_Success(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("json", "xml"))
	ctx := &policyv1alpha2.ResponseContext{
		ResponseBody:    &policyv1alpha2.Body{Content: []byte(`{"status":"ok"}`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/json; charset=utf-8"),
	}

	result := p.OnResponseBody(ctx, nil)
	mods, ok := result.(policyv1alpha2.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if mods.Body == nil || !strings.Contains(string(mods.Body), "<status>ok</status>") {
		t.Fatalf("expected transformed XML response body, got: %s", string(mods.Body))
	}
	if mods.DownstreamResponseHeaderModifications.HeadersToSet["content-type"] != "application/xml" {
		t.Fatalf("unexpected content-type: %s", mods.DownstreamResponseHeaderModifications.HeadersToSet["content-type"])
	}
}

func TestOnRequest_ContentTypeAndPayloadErrors(t *testing.T) {
	pJSONToXML := newConfiguredPolicy(t, configuredParams("xml", "json"))
	pXMLToJSON := newConfiguredPolicy(t, configuredParams("json", "xml"))

	wrongTypeCtx := &policyv1alpha2.RequestContext{
		Body:    &policyv1alpha2.Body{Content: []byte(`{"name":"x"}`), Present: true},
		Headers: createHeaders("content-type", "application/xml"),
	}
	res := pJSONToXML.OnRequestBody(wrongTypeCtx, nil)
	immediate, ok := res.(policyv1alpha2.ImmediateResponse)
	if !ok || immediate.StatusCode != 500 {
		t.Fatalf("expected 500 ImmediateResponse for wrong content type, got %T %#v", res, res)
	}

	invalidJSONCtx := &policyv1alpha2.RequestContext{
		Body:    &policyv1alpha2.Body{Content: []byte(`{"name":`), Present: true},
		Headers: createHeaders("content-type", "application/json"),
	}
	res = pJSONToXML.OnRequestBody(invalidJSONCtx, nil)
	immediate, ok = res.(policyv1alpha2.ImmediateResponse)
	if !ok || immediate.StatusCode != 500 {
		t.Fatalf("expected 500 ImmediateResponse for invalid JSON, got %T %#v", res, res)
	}

	invalidXMLCtx := &policyv1alpha2.RequestContext{
		Body:    &policyv1alpha2.Body{Content: []byte(`<root><name>x</root>`), Present: true},
		Headers: createHeaders("content-type", "application/xml"),
	}
	res = pXMLToJSON.OnRequestBody(invalidXMLCtx, nil)
	immediate, ok = res.(policyv1alpha2.ImmediateResponse)
	if !ok || immediate.StatusCode != 500 {
		t.Fatalf("expected 500 ImmediateResponse for invalid XML, got %T %#v", res, res)
	}

	errBody := parseErrorJSON(t, immediate.Body)
	if errBody["error"] != "Internal Server Error" {
		t.Fatalf("expected internal server error body, got %#v", errBody)
	}
}

func TestOnResponse_ContentTypeAndPayloadErrors(t *testing.T) {
	pXMLToJSON := newConfiguredPolicy(t, configuredParams("xml", "json"))
	pJSONToXML := newConfiguredPolicy(t, configuredParams("json", "xml"))

	wrongTypeCtx := &policyv1alpha2.ResponseContext{
		ResponseBody:    &policyv1alpha2.Body{Content: []byte(`<root/>`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/json"),
	}
	res := pXMLToJSON.OnResponseBody(wrongTypeCtx, nil)
	mods, ok := res.(policyv1alpha2.DownstreamResponseModifications)
	if !ok || mods.StatusCode == nil || *mods.StatusCode != 500 {
		t.Fatalf("expected 500 UpstreamResponseModifications for wrong content type, got %T %#v", res, res)
	}

	invalidJSONCtx := &policyv1alpha2.ResponseContext{
		ResponseBody:    &policyv1alpha2.Body{Content: []byte(`{"x":`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/json"),
	}
	res = pJSONToXML.OnResponseBody(invalidJSONCtx, nil)
	mods, ok = res.(policyv1alpha2.DownstreamResponseModifications)
	if !ok || mods.StatusCode == nil || *mods.StatusCode != 500 {
		t.Fatalf("expected 500 UpstreamResponseModifications for invalid JSON, got %T %#v", res, res)
	}

	invalidXMLCtx := &policyv1alpha2.ResponseContext{
		ResponseBody:    &policyv1alpha2.Body{Content: []byte(`<root><x></root>`), Present: true},
		ResponseHeaders: createHeaders("content-type", "application/xml"),
	}
	res = pXMLToJSON.OnResponseBody(invalidXMLCtx, nil)
	mods, ok = res.(policyv1alpha2.DownstreamResponseModifications)
	if !ok || mods.StatusCode == nil || *mods.StatusCode != 500 {
		t.Fatalf("expected 500 UpstreamResponseModifications for invalid XML, got %T %#v", res, res)
	}

	errBody := parseErrorJSON(t, mods.Body)
	if errBody["error"] != "Internal Server Error" {
		t.Fatalf("expected internal server error body, got %#v", errBody)
	}
}

func TestNoBodyPassThrough(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))

	reqCtx := &policyv1alpha2.RequestContext{
		Body:    &policyv1alpha2.Body{Content: []byte{}, Present: false},
		Headers: createHeaders("content-type", "application/json"),
	}
	reqResult := p.OnRequestBody(reqCtx, nil)
	reqMods, ok := reqResult.(policyv1alpha2.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", reqResult)
	}
	if reqMods.Body != nil {
		t.Fatalf("expected nil body for request pass-through, got %s", string(reqMods.Body))
	}

	respCtx := &policyv1alpha2.ResponseContext{
		ResponseBody:    &policyv1alpha2.Body{Content: []byte{}, Present: false},
		ResponseHeaders: createHeaders("content-type", "application/xml"),
	}
	respResult := p.OnResponseBody(respCtx, nil)
	respMods, ok := respResult.(policyv1alpha2.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", respResult)
	}
	if respMods.Body != nil {
		t.Fatalf("expected nil body for response pass-through, got %s", string(respMods.Body))
	}
}

func TestConversionHelpers(t *testing.T) {
	p := newConfiguredPolicy(t, configuredParams("xml", "json"))

	xmlData, err := p.convertJSONBytesToXML([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("convertJSONBytesToXML failed: %v", err)
	}
	if !strings.Contains(string(xmlData), "<a>1</a>") {
		t.Fatalf("unexpected XML: %s", xmlData)
	}

	jsonData, err := p.convertXMLToJSON([]byte(`<root><a>1</a></root>`))
	if err != nil {
		t.Fatalf("convertXMLToJSON failed: %v", err)
	}
	if !json.Valid(jsonData) {
		t.Fatalf("expected valid JSON output: %s", jsonData)
	}
}
