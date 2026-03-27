/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package semantictoolfiltering

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
)

// OnRequest handles request body processing for semantic tool filtering (v1alpha)
func (p *SemanticToolFilteringPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}

	if len(content) == 0 {
		slog.Debug("SemanticToolFiltering: Empty request body")
		return policy.UpstreamRequestModifications{}
	}

	// Handle based on format type (JSON or Text)
	if p.userQueryIsJson && p.toolsIsJson {
		// Pure JSON mode
		return p.handleJSONRequest(ctx, content)
	} else if !p.userQueryIsJson && !p.toolsIsJson {
		// Pure Text mode
		return p.handleTextRequest(ctx, content)
	} else {
		// Mixed mode
		return p.handleMixedRequest(ctx, content)
	}
}

// handleJSONRequest handles requests where both user query and tools are in JSON format
func (p *SemanticToolFilteringPolicy) handleJSONRequest(ctx *policy.RequestContext, content []byte) policy.RequestAction {
	// Parse request body as JSON
	var requestBody map[string]interface{}
	if err := json.Unmarshal(content, &requestBody); err != nil {
		return p.buildErrorResponse("Invalid JSON in request body", err)
	}

	// Extract user query using JSONPath
	userQuery, err := utils.ExtractStringValueFromJsonpath(content, p.queryJSONPath)
	if err != nil {
		return p.buildErrorResponse("Error extracting user query from JSONPath", err)
	}

	if userQuery == "" {
		slog.Debug("SemanticToolFiltering: Empty user query")
		return policy.UpstreamRequestModifications{}
	}

	// Extract tools array using JSONPath
	toolsJSON, err := utils.ExtractValueFromJsonpath(requestBody, p.toolsJSONPath)
	if err != nil {
		return p.buildErrorResponse("Error extracting tools from JSONPath", err)
	}

	// Parse tools array
	var tools []interface{}
	var toolsBytes []byte
	switch v := toolsJSON.(type) {
	case []byte:
		toolsBytes = v
	case string:
		toolsBytes = []byte(v)
	default:
		var err error
		toolsBytes, err = json.Marshal(v)
		if err != nil {
			return p.buildErrorResponse("Invalid tools format in request", err)
		}
	}
	if err := json.Unmarshal(toolsBytes, &tools); err != nil {
		return p.buildErrorResponse("Invalid tools format in request", err)
	}

	if len(tools) == 0 {
		slog.Debug("SemanticToolFiltering: No tools to filter")
		return policy.UpstreamRequestModifications{}
	}

	// Generate embedding for user query
	queryEmbedding, err := p.embeddingProvider.GetEmbedding(userQuery)
	if err != nil {
		slog.Error("SemanticToolFiltering: Error generating query embedding", "error", err)
		return p.buildErrorResponse("Error generating query embedding", err)
	}

	// Get embedding cache instance
	embeddingCache := GetEmbeddingCacheStoreInstance()
	apiId := ctx.APIId

	embeddingCache.AddAPICache(apiId)

	// Prepare embedding requests for all valid tools
	var embeddingRequests []toolEmbeddingRequest
	toolDescMap := make(map[string]string)                   // hashKey -> toolDesc for similarity calculation
	toolMapByHash := make(map[string]map[string]interface{}) // hashKey -> toolMap

	for _, toolRaw := range tools {
		toolMap, ok := toolRaw.(map[string]interface{})
		if !ok {
			slog.Warn("SemanticToolFiltering: Invalid tool format, skipping")
			continue
		}

		toolDesc := extractToolDescription(toolMap)
		if toolDesc == "" {
			slog.Warn("SemanticToolFiltering: No description found for tool, skipping",
				"toolName", toolMap["name"])
			continue
		}

		toolName, _ := toolMap["name"].(string)
		descHash := p.getCacheKey(toolDesc)

		embeddingRequests = append(embeddingRequests, toolEmbeddingRequest{
			Name:        toolName,
			Description: toolDesc,
			HashKey:     descHash,
		})
		toolDescMap[descHash] = toolDesc
		toolMapByHash[descHash] = toolMap
	}

	// Process embeddings with proper cache management (avoids cascade evictions)
	embeddingResults := p.processToolEmbeddingsWithCache(embeddingCache, apiId, embeddingRequests)

	// Calculate similarity scores for tools that have embeddings
	toolsWithScores := make([]ToolWithScore, 0, len(embeddingResults))
	for hashKey, result := range embeddingResults {
		toolMap := toolMapByHash[hashKey]
		if toolMap == nil {
			continue
		}

		similarity, err := cosineSimilarity(queryEmbedding, result.Embedding)
		if err != nil {
			slog.Warn("SemanticToolFiltering: Error calculating similarity, skipping",
				"error", err, "toolName", result.Name)
			continue
		}

		toolsWithScores = append(toolsWithScores, ToolWithScore{
			Tool:  toolMap,
			Score: similarity,
		})
	}

	if len(toolsWithScores) == 0 {
		slog.Debug("SemanticToolFiltering: No valid tools after embedding generation")
		return policy.UpstreamRequestModifications{}
	}

	// Filter tools based on selection mode
	filteredTools := p.filterTools(toolsWithScores)

	slog.Debug("SemanticToolFiltering: Filtered tools",
		"originalCount", len(tools),
		"filteredCount", len(filteredTools),
		"selectionMode", p.selectionMode)

	// Update request body with filtered tools
	if err := updateToolsInRequestBody(&requestBody, p.toolsJSONPath, filteredTools); err != nil {
		return p.buildErrorResponse("Error updating request body with filtered tools", err)
	}

	// Marshal modified request body
	modifiedBody, err := json.Marshal(requestBody)
	if err != nil {
		return p.buildErrorResponse("Error marshaling modified request body", err)
	}

	return policy.UpstreamRequestModifications{
		Body: modifiedBody,
	}
}

// handleTextRequest handles requests where both user query and tools are in text format with tags
func (p *SemanticToolFilteringPolicy) handleTextRequest(ctx *policy.RequestContext, content []byte) policy.RequestAction {
	contentStr := string(content)

	// Extract user query from <userq> tags
	userQuery, err := extractUserQueryFromText(contentStr)
	if err != nil {
		return p.buildErrorResponse("Error extracting user query from text", err)
	}

	if userQuery == "" {
		slog.Debug("SemanticToolFiltering: Empty user query")
		return policy.UpstreamRequestModifications{}
	}

	// Extract tools from <toolname> and <tooldescription> tags
	textTools, err := extractToolsFromText(contentStr)
	if err != nil {
		return p.buildErrorResponse("Error extracting tools from text", err)
	}

	if len(textTools) == 0 {
		slog.Debug("SemanticToolFiltering: No tools to filter")
		return policy.UpstreamRequestModifications{}
	}

	// Generate embedding for user query
	queryEmbedding, err := p.embeddingProvider.GetEmbedding(userQuery)

	if err != nil {
		slog.Error("SemanticToolFiltering: Error generating query embedding", "error", err)
		return p.buildErrorResponse("Error generating query embedding", err)
	}

	// Get embedding cache instance
	embeddingCache := GetEmbeddingCacheStoreInstance()
	apiId := ctx.APIId

	embeddingCache.AddAPICache(apiId)

	// Prepare embedding requests for all text tools
	var embeddingRequests []toolEmbeddingRequest
	textToolByHash := make(map[string]TextTool) // hashKey -> TextTool

	for _, tool := range textTools {
		toolText := fmt.Sprintf("%s: %s", tool.Name, tool.Description)
		textHash := p.getCacheKey(toolText)

		embeddingRequests = append(embeddingRequests, toolEmbeddingRequest{
			Name:        tool.Name,
			Description: toolText,
			HashKey:     textHash,
		})
		textToolByHash[textHash] = tool
	}

	// Process embeddings with proper cache management (avoids cascade evictions)
	embeddingResults := p.processToolEmbeddingsWithCache(embeddingCache, apiId, embeddingRequests)

	// Calculate similarity scores for tools that have embeddings
	type TextToolWithScore struct {
		Tool  TextTool
		Score float64
	}
	toolsWithScores := make([]TextToolWithScore, 0, len(embeddingResults))

	for hashKey, result := range embeddingResults {
		textTool, ok := textToolByHash[hashKey]
		if !ok {
			continue
		}

		similarity, err := cosineSimilarity(queryEmbedding, result.Embedding)
		if err != nil {
			slog.Warn("SemanticToolFiltering: Error calculating similarity, skipping",
				"error", err, "toolName", result.Name)
			continue
		}

		toolsWithScores = append(toolsWithScores, TextToolWithScore{
			Tool:  textTool,
			Score: similarity,
		})
	}

	if len(toolsWithScores) == 0 {
		slog.Debug("SemanticToolFiltering: No valid tools after embedding generation")
		return policy.UpstreamRequestModifications{}
	}

	// Sort by score in descending order
	sort.Slice(toolsWithScores, func(i, j int) bool {
		return toolsWithScores[i].Score > toolsWithScores[j].Score
	})

	// Filter based on selection mode
	filteredToolNames := make(map[string]bool)
	switch p.selectionMode {
	case SelectionModeTopK:
		limit := p.topK
		if limit > len(toolsWithScores) {
			limit = len(toolsWithScores)
		}
		for i := 0; i < limit; i++ {
			filteredToolNames[toolsWithScores[i].Tool.Name] = true
		}

	case SelectionModeThreshold:
		for _, item := range toolsWithScores {
			if item.Score >= p.threshold {
				filteredToolNames[item.Tool.Name] = true
			}
		}
	}

	// Rebuild text content with only filtered tools and strip all tags
	modifiedContent := rebuildTextWithFilteredTools(contentStr, textTools, filteredToolNames)
	modifiedContent = stripAllTags(modifiedContent)

	slog.Debug("SemanticToolFiltering: Filtered text tools",
		"originalCount", len(textTools),
		"filteredCount", len(filteredToolNames),
		"selectionMode", p.selectionMode)

	return policy.UpstreamRequestModifications{
		Body: []byte(modifiedContent),
	}
}

// handleMixedRequest handles requests where user query and tools have different formats
func (p *SemanticToolFilteringPolicy) handleMixedRequest(ctx *policy.RequestContext, content []byte) policy.RequestAction {
	// For mixed mode, parse based on each component's format
	contentStr := string(content)
	var userQuery string
	var err error

	// Extract user query based on format
	if p.userQueryIsJson {
		var requestBody map[string]interface{}
		if err := json.Unmarshal(content, &requestBody); err != nil {
			return p.buildErrorResponse("Invalid JSON in request body", err)
		}
		userQuery, err = utils.ExtractStringValueFromJsonpath(content, p.queryJSONPath)
		if err != nil {
			return p.buildErrorResponse("Error extracting user query from JSONPath", err)
		}
	} else {
		userQuery, err = extractUserQueryFromText(contentStr)
		if err != nil {
			return p.buildErrorResponse("Error extracting user query from text", err)
		}
	}

	if userQuery == "" {
		slog.Debug("SemanticToolFiltering: Empty user query")
		return policy.UpstreamRequestModifications{}
	}

	// Generate embedding for user query
	queryEmbedding, err := p.embeddingProvider.GetEmbedding(userQuery)
	if err != nil {
		slog.Error("SemanticToolFiltering: Error generating query embedding", "error", err)
		return p.buildErrorResponse("Error generating query embedding", err)
	}

	// Get embedding cache instance
	embeddingCache := GetEmbeddingCacheStoreInstance()
	apiId := ctx.APIId

	embeddingCache.AddAPICache(apiId)

	// Handle tools based on format
	if p.toolsIsJson {
		// Tools are in JSON format
		var requestBody map[string]interface{}
		if err := json.Unmarshal(content, &requestBody); err != nil {
			return p.buildErrorResponse("Invalid JSON in request body", err)
		}

		toolsJSON, err := utils.ExtractValueFromJsonpath(requestBody, p.toolsJSONPath)
		if err != nil {
			return p.buildErrorResponse("Error extracting tools from JSONPath", err)
		}

		var tools []interface{}
		var toolsBytes []byte
		switch v := toolsJSON.(type) {
		case []byte:
			toolsBytes = v
		case string:
			toolsBytes = []byte(v)
		default:
			var err error
			toolsBytes, err = json.Marshal(v)
			if err != nil {
				return p.buildErrorResponse("Invalid tools format in request", err)
			}
		}
		if err := json.Unmarshal(toolsBytes, &tools); err != nil {
			return p.buildErrorResponse("Invalid tools format in request", err)
		}

		if len(tools) == 0 {
			slog.Debug("SemanticToolFiltering: No tools to filter")
			return policy.UpstreamRequestModifications{}
		}

		var embeddingRequests []toolEmbeddingRequest
		toolMapByHash := make(map[string]map[string]interface{})

		for _, toolRaw := range tools {
			toolMap, ok := toolRaw.(map[string]interface{})
			if !ok {
				slog.Warn("SemanticToolFiltering: Invalid tool format, skipping")
				continue
			}

			toolDesc := extractToolDescription(toolMap)
			if toolDesc == "" {
				slog.Warn("SemanticToolFiltering: No description found for tool, skipping")
				continue
			}

			toolName, _ := toolMap["name"].(string)
			descHash := p.getCacheKey(toolDesc)

			embeddingRequests = append(embeddingRequests, toolEmbeddingRequest{
				Name:        toolName,
				Description: toolDesc,
				HashKey:     descHash,
			})
			toolMapByHash[descHash] = toolMap
		}

		embeddingResults := p.processToolEmbeddingsWithCache(embeddingCache, apiId, embeddingRequests)

		toolsWithScores := make([]ToolWithScore, 0, len(embeddingResults))
		for hashKey, result := range embeddingResults {
			toolMap := toolMapByHash[hashKey]
			if toolMap == nil {
				continue
			}

			similarity, err := cosineSimilarity(queryEmbedding, result.Embedding)
			if err != nil {
				slog.Warn("SemanticToolFiltering: Error calculating similarity, skipping", "error", err)
				continue
			}

			toolsWithScores = append(toolsWithScores, ToolWithScore{
				Tool:  toolMap,
				Score: similarity,
			})
		}

		if len(toolsWithScores) == 0 {
			slog.Debug("SemanticToolFiltering: No valid tools after embedding generation")
			return policy.UpstreamRequestModifications{}
		}

		filteredTools := p.filterTools(toolsWithScores)

		if err := updateToolsInRequestBody(&requestBody, p.toolsJSONPath, filteredTools); err != nil {
			return p.buildErrorResponse("Error updating request body with filtered tools", err)
		}

		modifiedBody, err := json.Marshal(requestBody)
		if err != nil {
			return p.buildErrorResponse("Error marshaling modified request body", err)
		}

		return policy.UpstreamRequestModifications{
			Body: modifiedBody,
		}
	} else {
		// Tools are in text format
		textTools, err := extractToolsFromText(contentStr)
		if err != nil {
			return p.buildErrorResponse("Error extracting tools from text", err)
		}

		if len(textTools) == 0 {
			slog.Debug("SemanticToolFiltering: No tools to filter")
			return policy.UpstreamRequestModifications{}
		}

		var embeddingRequests []toolEmbeddingRequest
		textToolByHash := make(map[string]TextTool)

		for _, tool := range textTools {
			toolText := fmt.Sprintf("%s: %s", tool.Name, tool.Description)
			textHash := p.getCacheKey(toolText)

			embeddingRequests = append(embeddingRequests, toolEmbeddingRequest{
				Name:        tool.Name,
				Description: toolText,
				HashKey:     textHash,
			})
			textToolByHash[textHash] = tool
		}

		embeddingResults := p.processToolEmbeddingsWithCache(embeddingCache, apiId, embeddingRequests)

		type TextToolWithScore struct {
			Tool  TextTool
			Score float64
		}
		toolsWithScores := make([]TextToolWithScore, 0, len(embeddingResults))

		for hashKey, result := range embeddingResults {
			textTool, ok := textToolByHash[hashKey]
			if !ok {
				continue
			}

			similarity, err := cosineSimilarity(queryEmbedding, result.Embedding)
			if err != nil {
				slog.Warn("SemanticToolFiltering: Error calculating similarity, skipping", "error", err)
				continue
			}

			toolsWithScores = append(toolsWithScores, TextToolWithScore{
				Tool:  textTool,
				Score: similarity,
			})
		}

		if len(toolsWithScores) == 0 {
			slog.Debug("SemanticToolFiltering: No valid tools after embedding generation")
			return policy.UpstreamRequestModifications{}
		}

		sort.Slice(toolsWithScores, func(i, j int) bool {
			return toolsWithScores[i].Score > toolsWithScores[j].Score
		})

		filteredToolNames := make(map[string]bool)
		switch p.selectionMode {
		case SelectionModeTopK:
			limit := p.topK
			if limit > len(toolsWithScores) {
				limit = len(toolsWithScores)
			}
			for i := 0; i < limit; i++ {
				filteredToolNames[toolsWithScores[i].Tool.Name] = true
			}

		case SelectionModeThreshold:
			for _, item := range toolsWithScores {
				if item.Score >= p.threshold {
					filteredToolNames[item.Tool.Name] = true
				}
			}
		}

		modifiedContent := rebuildTextWithFilteredTools(contentStr, textTools, filteredToolNames)
		modifiedContent = stripAllTags(modifiedContent)

		return policy.UpstreamRequestModifications{
			Body: []byte(modifiedContent),
		}
	}
}

// buildErrorResponse builds an error response
func (p *SemanticToolFilteringPolicy) buildErrorResponse(message string, err error) policy.RequestAction {
	// Log a warning with error details for diagnostics, but do not expose
	// internal error details to clients. Continue the request unmodified.
	if err != nil {
		slog.Warn("SemanticToolFiltering: "+message, "error", err)
	} else {
		slog.Warn("SemanticToolFiltering: " + message)
	}

	// Return a pass-through action so the original request proceeds unchanged.
	return policy.UpstreamRequestModifications{}
}
