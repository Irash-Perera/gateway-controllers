/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package semanticcache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
	embeddingproviders "github.com/wso2/api-platform/sdk/utils/embeddingproviders"
	vectordbproviders "github.com/wso2/api-platform/sdk/utils/vectordbproviders"
)

const (
	// MetadataKeyEmbedding is the key used to store embedding in metadata between request and response phases
	MetadataKeyEmbedding = "semantic_cache_embedding"
	// MetadataKeyAPIID is the key used to store API ID in metadata
	MetadataKeyAPIID = "semantic_cache_api_id"
)

// SemanticCachePolicy implements semantic caching for LLM responses
type SemanticCachePolicy struct {
	embeddingConfig     embeddingproviders.EmbeddingProviderConfig
	vectorStoreConfig   vectordbproviders.VectorDBProviderConfig
	embeddingProvider   embeddingproviders.EmbeddingProvider
	vectorStoreProvider vectordbproviders.VectorDBProvider
	jsonPath            string
	threshold           float64
}

// GetPolicy is the v1alpha factory entry point (loaded by v1alpha kernels).
// The returned concrete type also satisfies policyv1alpha2 phase interfaces
// (StreamingResponsePolicy, RequestPolicy, ResponsePolicy), so v1alpha2 kernels
// can discover those capabilities via type assertions even when using this factory.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SemanticCachePolicy{}

	// Parse and validate parameters
	if err := parseParams(params, p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Initialize embedding provider
	embeddingProvider, err := createEmbeddingProvider(p.embeddingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding provider: %w", err)
	}
	p.embeddingProvider = embeddingProvider

	// Initialize vector store provider
	vectorStoreProvider, err := createVectorDBProvider(p.vectorStoreConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vector store provider: %w", err)
	}
	p.vectorStoreProvider = vectorStoreProvider

	// Create index during initialization
	if err := p.vectorStoreProvider.CreateIndex(); err != nil {
		return nil, fmt.Errorf("failed to create vector store index: %w", err)
	}

	slog.Debug("SemanticCache: Policy initialized", "embeddingProvider", embeddingProvider, "vectorStoreProvider", vectorStoreProvider, "similarityThreshold", p.threshold)

	return p, nil
}

// GetPolicyV2 is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicyV2(
	metadata policyv1alpha2.PolicyMetadata,
	params map[string]interface{},
) (policyv1alpha2.Policy, error) {
	p, err := GetPolicy(policy.PolicyMetadata{
		RouteName:  metadata.RouteName,
		APIId:      metadata.APIId,
		APIName:    metadata.APIName,
		APIVersion: metadata.APIVersion,
		AttachedTo: policy.Level(metadata.AttachedTo),
	}, params)
	if err != nil {
		return nil, err
	}
	return p.(*SemanticCachePolicy), nil
}

// parseParams parses and validates parameters from the params map
func parseParams(params map[string]interface{}, p *SemanticCachePolicy) error {
	// Required parameters
	embeddingProvider, ok := params["embeddingProvider"].(string)
	if !ok || embeddingProvider == "" {
		return fmt.Errorf("'embeddingProvider' parameter is required")
	}

	vectorStoreProvider, ok := params["vectorStoreProvider"].(string)
	if !ok || vectorStoreProvider == "" {
		return fmt.Errorf("'vectorStoreProvider' parameter is required")
	}

	thresholdRaw, ok := params["similarityThreshold"]
	if !ok {
		return fmt.Errorf("'similarityThreshold' parameter is required")
	}
	threshold, err := extractFloat64(thresholdRaw)
	if err != nil {
		return fmt.Errorf("'similarityThreshold' must be a number: %w", err)
	}
	if threshold < 0.0 || threshold > 1.0 {
		return fmt.Errorf("'similarityThreshold' must be between 0.0 and 1.0 (similarity range)")
	}

	p.threshold = threshold

	// Parse embedding provider config
	p.embeddingConfig = embeddingproviders.EmbeddingProviderConfig{
		EmbeddingProvider: embeddingProvider,
	}

	// Required for OPENAI, MISTRAL, AZURE_OPENAI
	if endpoint, ok := params["embeddingEndpoint"].(string); ok && endpoint != "" {
		p.embeddingConfig.EmbeddingEndpoint = endpoint
	} else {
		return fmt.Errorf("'embeddingEndpoint' is required for %s provider", embeddingProvider)
	}

	// embeddingModel is required for OPENAI and MISTRAL, but not for AZURE_OPENAI
	// For AZURE_OPENAI, deployment name is in the endpoint URL, so model can be empty
	var embeddingModel string
	if model, ok := params["embeddingModel"].(string); ok && model != "" {
		embeddingModel = model
	} else if embeddingProvider == "OPENAI" || embeddingProvider == "MISTRAL" {
		return fmt.Errorf("'embeddingModel' is required for %s provider", embeddingProvider)
	}
	// Always set EmbeddingModel explicitly (empty string is allowed for AZURE_OPENAI)
	p.embeddingConfig.EmbeddingModel = embeddingModel

	if apiKey, ok := params["apiKey"].(string); ok && apiKey != "" {
		p.embeddingConfig.APIKey = apiKey
	} else {
		return fmt.Errorf("'apiKey' is required for %s provider", embeddingProvider)
	}

	// Set header name based on provider type
	// Azure OpenAI uses "api-key", others use "Authorization"
	if embeddingProvider == "AZURE_OPENAI" {
		p.embeddingConfig.AuthHeaderName = "api-key"
	} else {
		p.embeddingConfig.AuthHeaderName = "Authorization"
	}

	// Parse vector store provider config
	// Threshold is stored as similarity threshold (0-1, higher is better)
	p.vectorStoreConfig = vectordbproviders.VectorDBProviderConfig{
		VectorStoreProvider: vectorStoreProvider,
		Threshold:           fmt.Sprintf("%.2f", p.threshold),
	}

	if dbHost, ok := params["dbHost"].(string); ok && dbHost != "" {
		p.vectorStoreConfig.DBHost = dbHost
	} else {
		return fmt.Errorf("'dbHost' is required")
	}

	if dbPortRaw, ok := params["dbPort"]; ok {
		dbPort, err := extractInt(dbPortRaw)
		if err != nil {
			return fmt.Errorf("'dbPort' must be a number: %w", err)
		}
		p.vectorStoreConfig.DBPort = dbPort
	} else {
		return fmt.Errorf("'dbPort' is required")
	}

	if embeddingDim, ok := params["embeddingDimension"]; ok {
		dim, err := extractInt(embeddingDim)
		if err != nil {
			return fmt.Errorf("'embeddingDimension' must be a number: %w", err)
		}
		p.vectorStoreConfig.EmbeddingDimension = strconv.Itoa(dim)
	} else {
		return fmt.Errorf("'embeddingDimension' is required")
	}

	if username, ok := params["username"].(string); ok {
		p.vectorStoreConfig.Username = username
	}

	if password, ok := params["password"].(string); ok {
		p.vectorStoreConfig.Password = password
	}

	if database, ok := params["database"].(string); ok {
		p.vectorStoreConfig.DatabaseName = database
	}

	if ttlRaw, ok := params["ttl"]; ok {
		ttl, err := extractInt(ttlRaw)
		if err != nil {
			return fmt.Errorf("'ttl' must be a number: %w", err)
		}
		p.vectorStoreConfig.TTL = strconv.Itoa(ttl)
	}

	// Optional JSONPath for extracting text from request body
	if jsonPath, ok := params["jsonPath"].(string); ok {
		p.jsonPath = jsonPath
	}

	return nil
}

// extractFloat64 safely extracts a float64 from various types
func extractFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot convert %q to float64: %w", v, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

// extractInt safely extracts an integer from various types
func extractInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("expected an integer but got %v", v)
		}
		return int(v), nil
	case string:
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("cannot convert %q to int: %w", v, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// createEmbeddingProvider creates a new embedding provider based on the config
func createEmbeddingProvider(config embeddingproviders.EmbeddingProviderConfig) (embeddingproviders.EmbeddingProvider, error) {
	var provider embeddingproviders.EmbeddingProvider

	switch config.EmbeddingProvider {
	case "OPENAI":
		provider = &embeddingproviders.OpenAIEmbeddingProvider{}
	case "MISTRAL":
		provider = &embeddingproviders.MistralEmbeddingProvider{}
	case "AZURE_OPENAI":
		provider = &embeddingproviders.AzureOpenAIEmbeddingProvider{}
	default:
		return nil, fmt.Errorf("unsupported embedding provider: %s", config.EmbeddingProvider)
	}

	if err := provider.Init(config); err != nil {
		return nil, fmt.Errorf("failed to initialize embedding provider: %w", err)
	}

	return provider, nil
}

// createVectorDBProvider creates a new vector DB provider based on the config
func createVectorDBProvider(config vectordbproviders.VectorDBProviderConfig) (vectordbproviders.VectorDBProvider, error) {
	var provider vectordbproviders.VectorDBProvider

	switch config.VectorStoreProvider {
	case "REDIS":
		provider = &vectordbproviders.RedisVectorDBProvider{}
	case "MILVUS":
		provider = &vectordbproviders.MilvusVectorDBProvider{}
	default:
		return nil, fmt.Errorf("unsupported vector store provider: %s", config.VectorStoreProvider)
	}

	if err := provider.Init(config); err != nil {
		return nil, fmt.Errorf("failed to initialize vector store provider: %w", err)
	}

	return provider, nil
}

// Mode returns the processing mode for this policy
func (p *SemanticCachePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequest handles request body processing for semantic caching (v1alpha interface)
func (p *SemanticCachePolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}

	// Extract text from request body using JSONPath if specified
	textToEmbed := string(content)
	if p.jsonPath != "" && len(content) > 0 {
		extracted, err := utils.ExtractStringValueFromJsonpath(content, p.jsonPath)
		if err != nil {
			// JSONPath extraction failed - return error response
			return p.buildErrorResponse("Error extracting value from JSONPath", err)
		}
		textToEmbed = extracted
	}

	// If no content to embed, continue to upstream
	if len(textToEmbed) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	// Generate embedding
	embedding, err := p.embeddingProvider.GetEmbedding(textToEmbed)
	if err != nil {
		slog.Debug("SemanticCache: Error generating embedding", "error", err)
		// Log error but don't block request
		return policy.UpstreamRequestModifications{}
	}

	// Store embedding in metadata for response phase
	if ctx.Metadata == nil {
		ctx.Metadata = make(map[string]interface{})
	}
	embeddingBytes, err := json.Marshal(embedding)
	if err == nil {
		ctx.Metadata[MetadataKeyEmbedding] = string(embeddingBytes)
	}

	// Get API ID from context (use APIName and APIVersion to create unique ID)
	apiID := fmt.Sprintf("%s:%s", ctx.APIName, ctx.APIVersion)

	// Cosine similarity embedders (e.g. Mistral) have a floor of ~0.6 — even completely
	// unrelated texts score that high. Map [0.6, 1.0] → [0, 1] so the user-supplied
	// threshold works across the full semantic range.
	// effectiveThreshold = 0.6 + userThreshold * 0.4
	const minSimilarityBaseline = 0.6
	effectiveThreshold := minSimilarityBaseline + p.threshold*(1.0-minSimilarityBaseline)

	// Check cache for similar response
	// Threshold needs to be a string for the vector DB provider
	cacheFilter := map[string]interface{}{
		"threshold": fmt.Sprintf("%.4f", effectiveThreshold),
		"api_id":    apiID,
		"ctx":       context.Background(), // Vector DB providers need context
	}

	cacheResponse, err := p.vectorStoreProvider.Retrieve(embedding, cacheFilter)
	if err != nil {
		slog.Debug("SemanticCache: Cache retrieval error", "error", err, "apiID", apiID)
		// Cache miss or error - continue to upstream
		return policy.UpstreamRequestModifications{}
	}

	// Check if we got a valid cache response
	// Retrieve returns empty CacheResponse on no match or threshold not met
	if cacheResponse.ResponsePayload == nil || len(cacheResponse.ResponsePayload) == 0 {
		slog.Debug("SemanticCache: Cache miss", "apiID", apiID, "threshold", p.threshold)
		// Cache miss - continue to upstream
		return policy.UpstreamRequestModifications{}
	}

	// Cache hit - return cached response immediately
	slog.Debug("SemanticCache: Cache hit", "apiID", apiID)
	responseBytes, err := json.Marshal(cacheResponse.ResponsePayload)
	if err != nil {
		return policy.UpstreamRequestModifications{}
	}

	return policy.ImmediateResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":   "application/json",
			"X-Cache-Status": "HIT",
		},
		Body: responseBytes,
	}
}

// OnRequestBody implements the v1alpha2 body-phase request handler.
func (p *SemanticCachePolicy) OnRequestBody(ctx *policyv1alpha2.RequestContext, params map[string]interface{}) policyv1alpha2.RequestAction {
	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}

	// Extract text from request body using JSONPath if specified
	textToEmbed := string(content)
	if p.jsonPath != "" && len(content) > 0 {
		extracted, err := utils.ExtractStringValueFromJsonpath(content, p.jsonPath)
		if err != nil {
			// JSONPath extraction failed - return error response
			return p.buildErrorResponseV2("Error extracting value from JSONPath", err)
		}
		textToEmbed = extracted
	}

	// If no content to embed, continue to upstream
	if len(textToEmbed) == 0 {
		return policyv1alpha2.UpstreamRequestModifications{}
	}

	// Generate embedding
	embedding, err := p.embeddingProvider.GetEmbedding(textToEmbed)
	if err != nil {
		slog.Debug("SemanticCache: Error generating embedding", "error", err)
		// Log error but don't block request
		return policyv1alpha2.UpstreamRequestModifications{}
	}

	// Store embedding in metadata for response phase
	if ctx.Metadata == nil {
		ctx.Metadata = make(map[string]interface{})
	}
	embeddingBytes, err := json.Marshal(embedding)
	if err == nil {
		ctx.Metadata[MetadataKeyEmbedding] = string(embeddingBytes)
	}

	// Get API ID from context (use APIName and APIVersion to create unique ID)
	apiID := fmt.Sprintf("%s:%s", ctx.APIName, ctx.APIVersion)

	// Cosine similarity embedders (e.g. Mistral) have a floor of ~0.6 — even completely
	// unrelated texts score that high. Map [0.6, 1.0] → [0, 1] so the user-supplied
	// threshold works across the full semantic range.
	// effectiveThreshold = 0.6 + userThreshold * 0.4
	const minSimilarityBaseline = 0.6
	effectiveThreshold := minSimilarityBaseline + p.threshold*(1.0-minSimilarityBaseline)

	// Check cache for similar response
	// Threshold needs to be a string for the vector DB provider
	cacheFilter := map[string]interface{}{
		"threshold": fmt.Sprintf("%.4f", effectiveThreshold),
		"api_id":    apiID,
		"ctx":       context.Background(), // Vector DB providers need context
	}

	cacheResponse, err := p.vectorStoreProvider.Retrieve(embedding, cacheFilter)
	if err != nil {
		slog.Debug("SemanticCache: Cache retrieval error", "error", err, "apiID", apiID)
		// Cache miss or error - continue to upstream
		return policyv1alpha2.UpstreamRequestModifications{}
	}

	// Check if we got a valid cache response
	// Retrieve returns empty CacheResponse on no match or threshold not met
	if cacheResponse.ResponsePayload == nil || len(cacheResponse.ResponsePayload) == 0 {
		slog.Debug("SemanticCache: Cache miss", "apiID", apiID, "threshold", effectiveThreshold)
		// Cache miss - continue to upstream
		return policyv1alpha2.UpstreamRequestModifications{}
	}

	// Cache hit - return cached response immediately
	slog.Debug("SemanticCache: Cache hit", "apiID", apiID)
	responseBytes, err := json.Marshal(cacheResponse.ResponsePayload)
	if err != nil {
		return policyv1alpha2.UpstreamRequestModifications{}
	}

	return policyv1alpha2.ImmediateResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":   "application/json",
			"X-Cache-Status": "HIT",
		},
		Body: responseBytes,
	}
}

// OnResponse handles response body processing for semantic caching (v1alpha interface)
func (p *SemanticCachePolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	// Only cache successful responses (200 status code)
	if ctx.ResponseStatus != 200 {
		slog.Debug("SemanticCache: Skipping cache for non-200 response", "statusCode", ctx.ResponseStatus)
		return policy.UpstreamResponseModifications{}
	}

	var content []byte
	if ctx.ResponseBody != nil {
		content = ctx.ResponseBody.Content
	}

	if len(content) == 0 {
		return policy.UpstreamResponseModifications{}
	}

	// Retrieve embedding from metadata (stored in request phase)
	embeddingStr, ok := ctx.Metadata[MetadataKeyEmbedding].(string)
	if !ok || embeddingStr == "" {
		slog.Debug("SemanticCache: No embedding found in metadata, skipping cache storage")
		return policy.UpstreamResponseModifications{}
	}

	// Deserialize embedding
	var embedding []float32
	if err := json.Unmarshal([]byte(embeddingStr), &embedding); err != nil {
		return policy.UpstreamResponseModifications{}
	}

	// Parse response body
	var responseData map[string]interface{}
	if err := json.Unmarshal(content, &responseData); err != nil {
		return policy.UpstreamResponseModifications{}
	}

	// Get API ID from context (use APIName and APIVersion to create unique ID)
	apiID := fmt.Sprintf("%s:%s", ctx.APIName, ctx.APIVersion)
	if apiID == ":" {
		// Fallback to route name if API info not available
		apiID = ctx.RequestID
	}

	// Store in cache
	cacheResponse := vectordbproviders.CacheResponse{
		ResponsePayload:     responseData,
		RequestHash:         uuid.New().String(),
		ResponseFetchedTime: time.Now(),
	}

	cacheFilter := map[string]interface{}{
		"api_id": apiID,
		"ctx":    context.Background(), // Vector DB providers need context
	}

	if err := p.vectorStoreProvider.Store(embedding, cacheResponse, cacheFilter); err != nil {
		slog.Debug("SemanticCache: Error storing in cache", "error", err, "apiID", apiID)
		// Log error but don't modify response
		return policy.UpstreamResponseModifications{}
	}

	slog.Debug("SemanticCache: Response cached successfully", "apiID", apiID)
	return policy.UpstreamResponseModifications{}
}

// buildErrorResponse builds an error response for JSONPath extraction failures (v1alpha)
func (p *SemanticCachePolicy) buildErrorResponse(message string, err error) policy.RequestAction {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}

	responseBody := map[string]interface{}{
		"type":    "SEMANTIC_CACHE",
		"message": errorMsg,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"SEMANTIC_CACHE","message":"Internal error"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: 400,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}

// OnResponseBody handles response body processing for semantic caching.
func (p *SemanticCachePolicy) OnResponseBody(ctx *policyv1alpha2.ResponseContext, _ map[string]interface{}) policyv1alpha2.ResponseAction {
	return p.processResponseBodyV2(ctx)
}

// processResponseBody handles response body processing for semantic caching.
func (p *SemanticCachePolicy) processResponseBodyV2(ctx *policyv1alpha2.ResponseContext) policyv1alpha2.ResponseAction {
	// Only cache successful responses (200 status code)
	if ctx.ResponseStatus != 200 {
		slog.Debug("SemanticCache: Skipping cache for non-200 response", "statusCode", ctx.ResponseStatus)
		return policyv1alpha2.DownstreamResponseModifications{}
	}

	var content []byte
	if ctx.ResponseBody != nil {
		content = ctx.ResponseBody.Content
	}

	if len(content) == 0 {
		return policyv1alpha2.DownstreamResponseModifications{}
	}

	// Retrieve embedding from metadata (stored in request phase)
	embeddingStr, ok := ctx.Metadata[MetadataKeyEmbedding].(string)
	if !ok || embeddingStr == "" {
		slog.Debug("SemanticCache: No embedding found in metadata, skipping cache storage")
		return policyv1alpha2.DownstreamResponseModifications{}
	}

	// Deserialize embedding
	var embedding []float32
	if err := json.Unmarshal([]byte(embeddingStr), &embedding); err != nil {
		return policyv1alpha2.DownstreamResponseModifications{}
	}

	// Parse response body
	var responseData map[string]interface{}
	if err := json.Unmarshal(content, &responseData); err != nil {
		if isSSEResponse(ctx.ResponseHeaders) {
			slog.Info("SemanticCache: Skipping cache storage for streaming response; buffered SSE events are not supported")
		} else {
			slog.Info("SemanticCache: Failed to parse response body, skipping cache storage", "error", err)
		}
		return policyv1alpha2.DownstreamResponseModifications{}
	}

	// Get API ID from context (use APIName and APIVersion to create unique ID)
	apiID := fmt.Sprintf("%s:%s", ctx.APIName, ctx.APIVersion)
	if apiID == ":" {
		// Fallback to route name if API info not available
		apiID = ctx.RequestID
	}

	// Store in cache
	cacheResponse := vectordbproviders.CacheResponse{
		ResponsePayload:     responseData,
		RequestHash:         uuid.New().String(),
		ResponseFetchedTime: time.Now(),
	}

	cacheFilter := map[string]interface{}{
		"api_id": apiID,
		"ctx":    context.Background(), // Vector DB providers need context
	}

	if err := p.vectorStoreProvider.Store(embedding, cacheResponse, cacheFilter); err != nil {
		slog.Debug("SemanticCache: Error storing in cache", "error", err, "apiID", apiID)
		// Log error but don't modify response
		return policyv1alpha2.DownstreamResponseModifications{}
	}

	slog.Debug("SemanticCache: Response cached successfully", "apiID", apiID)
	return policyv1alpha2.DownstreamResponseModifications{}
}

// isSSEResponse reports whether the response Content-Type indicates an SSE stream.
func isSSEResponse(headers *policyv1alpha2.Headers) bool {
	if headers == nil {
		return false
	}
	for _, v := range headers.Get("content-type") {
		if v == "text/event-stream" {
			return true
		}
	}
	return false
}

// buildErrorResponseV2 builds a v1alpha2 error response for JSONPath extraction failures.
func (p *SemanticCachePolicy) buildErrorResponseV2(message string, err error) policyv1alpha2.RequestAction {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}

	responseBody := map[string]interface{}{
		"type":    "SEMANTIC_CACHE",
		"message": errorMsg,
	}

	bodyBytes, marshalErr := json.Marshal(responseBody)
	if marshalErr != nil {
		bodyBytes = []byte(`{"type":"SEMANTIC_CACHE","message":"Internal error"}`)
	}

	return policyv1alpha2.ImmediateResponse{
		StatusCode: 400,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}
