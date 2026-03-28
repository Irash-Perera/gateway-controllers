package ratelimit

import (
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestCostExtractor_ExtractResponseCostV2_PlainBody(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"usage":{"prompt_tokens":42}}`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from response body to succeed")
	}
	if cost != 42 {
		t.Fatalf("expected extracted cost to be 42, got %v", cost)
	}
}

func TestCostExtractor_ExtractResponseCostV2_FallsBackToDefault(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 7,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"invalid json`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if extracted {
		t.Fatal("expected extraction to fail for invalid JSON payload")
	}
	if cost != 7 {
		t.Fatalf("expected default cost 7, got %v", cost)
	}
}

func TestCostExtractor_ExtractResponseCostV2_SSEBody(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	sseBody := "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n" +
		"data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":62,\"total_tokens\":162}}\n" +
		"data: [DONE]\n"

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"text/event-stream"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(sseBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from SSE body to succeed")
	}
	if cost != 100 {
		t.Fatalf("expected extracted cost to be 100 (prompt_tokens), got %v", cost)
	}
}

func TestCostExtractor_ExtractResponseCostV2_SSEBody_CompletionTokens(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.completion_tokens",
				Multiplier: 2,
			},
		},
	})

	sseBody := "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n" +
		"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":30,\"total_tokens\":80}}\n" +
		"data: [DONE]\n"

	ctx := &policy.ResponseContext{
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(sseBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from SSE body to succeed")
	}
	// 30 * 2 (multiplier) = 60
	if cost != 60 {
		t.Fatalf("expected extracted cost to be 60 (30 * 2), got %v", cost)
	}
}

func TestExtractFromSSEBodyBytes_NoMatch(t *testing.T) {
	sseBody := []byte(
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n" +
			"data: [DONE]\n",
	)
	_, ok := extractFromSSEBodyBytes(sseBody, "$.usage.prompt_tokens")
	if ok {
		t.Error("expected no match when SSE events don't have usage")
	}
}

func TestExtractFromBodyBytes_PlainJSON_StillWorks(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":42}}`)
	cost, ok := extractFromBodyBytes(body, "$.usage.prompt_tokens")
	if !ok {
		t.Fatal("expected extraction from plain JSON to succeed")
	}
	if cost != 42 {
		t.Fatalf("expected 42, got %v", cost)
	}
}

// anthropicSSEBody is the full buffered Anthropic SSE response used across multiple tests.
// The message_delta event carries usage: input_tokens=10, output_tokens=20.
var anthropicSSEBody = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-3-5-sonnet-20241022\",\"stop_reason\":null,\"usage\":{\"input_tokens\":0,\"output_tokens\":0}}}\n" +
	"\n" +
	"event: content_block_start\n" +
	"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n" +
	"\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n" +
	"\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n" +
	"\n" +
	"event: message_delta\n" +
	"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":10,\"output_tokens\":20}}\n" +
	"\n" +
	"event: message_stop\n" +
	"data: {\"type\":\"message_stop\"}\n"

func TestCostExtractor_AnthropicSSE_InputTokens(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.input_tokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"text/event-stream"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(anthropicSSEBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from Anthropic SSE body to succeed")
	}
	if cost != 10 {
		t.Fatalf("expected input_tokens=10, got %v", cost)
	}
}

func TestCostExtractor_AnthropicSSE_OutputTokens(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.output_tokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"text/event-stream"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(anthropicSSEBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from Anthropic SSE body to succeed")
	}
	if cost != 20 {
		t.Fatalf("expected output_tokens=20, got %v", cost)
	}
}

func TestCostExtractor_AnthropicSSE_WithMultiplier(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.output_tokens",
				Multiplier: 2,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(anthropicSSEBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from Anthropic SSE body to succeed")
	}
	// 20 * 2 = 40
	if cost != 40 {
		t.Fatalf("expected output_tokens=20 * multiplier=2 = 40, got %v", cost)
	}
}

// ─── Amazon Bedrock ───────────────────────────────────────────────────────────

// bedrockStreamingBody is a buffered Bedrock streaming response.
// Bedrock does NOT embed usage in the body — usage comes from response headers.
var bedrockStreamingBody = "data: {\"chunk\":{\"bytes\":\"Hello\"}}\n" +
	"data: {\"chunk\":{\"bytes\":\" world\"}}\n" +
	"data: {\"chunk\":{\"bytes\":\"!\"}}\n"

// TestCostExtractor_BedrockStreaming_InputTokensFromHeader verifies that
// x-amzn-bedrock-input-token-count is extracted via CostSourceResponseHeader.
func TestCostExtractor_BedrockStreaming_InputTokensFromHeader(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseHeader,
				Key:        "x-amzn-bedrock-input-token-count",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"x-amzn-bedrock-input-token-count":  {"10"},
			"x-amzn-bedrock-output-token-count": {"20"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(bedrockStreamingBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from response header to succeed")
	}
	if cost != 10 {
		t.Fatalf("expected input_token_count=10, got %v", cost)
	}
}

// TestCostExtractor_BedrockStreaming_OutputTokensFromHeader verifies that
// x-amzn-bedrock-output-token-count is extracted via CostSourceResponseHeader.
func TestCostExtractor_BedrockStreaming_OutputTokensFromHeader(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseHeader,
				Key:        "x-amzn-bedrock-output-token-count",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"x-amzn-bedrock-input-token-count":  {"10"},
			"x-amzn-bedrock-output-token-count": {"20"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(bedrockStreamingBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from response header to succeed")
	}
	if cost != 20 {
		t.Fatalf("expected output_token_count=20, got %v", cost)
	}
}

// TestCostExtractor_BedrockStreaming_CombinedHeaderCost verifies that
// input + output token counts are summed when both header sources are configured.
func TestCostExtractor_BedrockStreaming_CombinedHeaderCost(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseHeader,
				Key:        "x-amzn-bedrock-input-token-count",
				Multiplier: 1,
			},
			{
				Type:       CostSourceResponseHeader,
				Key:        "x-amzn-bedrock-output-token-count",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"x-amzn-bedrock-input-token-count":  {"10"},
			"x-amzn-bedrock-output-token-count": {"20"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(bedrockStreamingBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from response headers to succeed")
	}
	// 10 + 20 = 30
	if cost != 30 {
		t.Fatalf("expected combined cost=30, got %v", cost)
	}
}

// TestCostExtractor_BedrockStreaming_WithMultiplier verifies that the multiplier
// is applied to the header-sourced token count.
func TestCostExtractor_BedrockStreaming_WithMultiplier(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseHeader,
				Key:        "x-amzn-bedrock-output-token-count",
				Multiplier: 2,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"x-amzn-bedrock-output-token-count": {"20"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(bedrockStreamingBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction to succeed")
	}
	// 20 * 2 = 40
	if cost != 40 {
		t.Fatalf("expected 20 * 2 = 40, got %v", cost)
	}
}

// TestCostExtractor_BedrockStreaming_BodyYieldsNoMatch confirms that the Bedrock
// streaming body (chunk format) does not match a usage JSONPath.
// Usage must be sourced from response headers, not the body.
func TestCostExtractor_BedrockStreaming_BodyYieldsNoMatch(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:     CostSourceResponseBody,
				JSONPath: "$.usage.inputTokens",
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(bedrockStreamingBody),
		},
	}

	_, extracted := extractor.ExtractResponseCost(ctx)
	if extracted {
		t.Error("expected no extraction: Bedrock streaming body carries no usage field")
	}
}

// TestCostExtractor_BedrockNonStream_InputTokens verifies extraction of inputTokens
// from a Bedrock non-streaming JSON response body.
func TestCostExtractor_BedrockNonStream_InputTokens(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.inputTokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"completion":"Hello world","usage":{"inputTokens":10,"outputTokens":20}}`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from non-stream response body to succeed")
	}
	if cost != 10 {
		t.Fatalf("expected inputTokens=10, got %v", cost)
	}
}

// TestCostExtractor_BedrockNonStream_OutputTokens verifies extraction of outputTokens
// from a Bedrock non-streaming JSON response body.
func TestCostExtractor_BedrockNonStream_OutputTokens(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.outputTokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"completion":"Hello world","usage":{"inputTokens":10,"outputTokens":20}}`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from non-stream response body to succeed")
	}
	if cost != 20 {
		t.Fatalf("expected outputTokens=20, got %v", cost)
	}
}

// TestCostExtractor_BedrockNonStream_CombinedCost verifies that inputTokens and
// outputTokens are summed when both body sources are configured.
func TestCostExtractor_BedrockNonStream_CombinedCost(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.inputTokens",
				Multiplier: 1,
			},
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.outputTokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"completion":"Hello world","usage":{"inputTokens":10,"outputTokens":20}}`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction to succeed")
	}
	// 10 + 20 = 30
	if cost != 30 {
		t.Fatalf("expected combined cost=30 (10+20), got %v", cost)
	}
}

func TestCostExtractor_AnthropicSSE_OnlyMessageDeltaMatches(t *testing.T) {
	// content_block_delta events have a "delta" field but no "usage" — they must not match.
	_, ok := extractFromSSEBodyBytes([]byte(anthropicSSEBody), "$.usage.output_tokens")
	if !ok {
		t.Fatal("expected a match from message_delta event")
	}

	// Verify that a body with only content_block_delta events (no message_delta) yields no match.
	noUsageBody := "event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n" +
		"\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n"

	_, ok = extractFromSSEBodyBytes([]byte(noUsageBody), "$.usage.output_tokens")
	if ok {
		t.Error("expected no match when no event carries $.usage.output_tokens")
	}
}
