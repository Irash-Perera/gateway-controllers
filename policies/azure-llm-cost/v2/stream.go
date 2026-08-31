/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package azurellmcost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
	streamAccumKey = "azure-llm-cost:stream-accum"
)

func isSSEContent(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// normalizeStreamBody merges SSE events so the parsers work on either shape.
func normalizeStreamBody(body []byte) ([]byte, error) {
	if isSSEContent(body) {
		return mergeSSEEvents(body)
	}
	return body, nil
}

// mergeSSEEvents shallow-merges top-level keys, later events winning, and
// deep-merges "usage". Later-wins matters: Azure's first chunk has an empty
// "model" that later chunks replace.
func mergeSSEEvents(body []byte) ([]byte, error) {
	var events [][]byte
	var fields [][]byte

	// An event may split its payload over several data fields, joined on dispatch.
	dispatch := func() {
		for _, payload := range eventPayloads(fields) {
			if json.Valid(payload) {
				events = append(events, payload)
			}
		}
		fields = nil
	}

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "":
			dispatch()
		case strings.HasPrefix(line, sseDataPrefix):
			value := strings.TrimSpace(strings.TrimPrefix(line, sseDataPrefix))
			if value == "" || value == sseDone {
				continue
			}
			fields = append(fields, []byte(value))
		case strings.HasPrefix(line, sseEventPrefix):
			value := strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
			if value != "" && value != sseDone && json.Valid([]byte(value)) {
				events = append(events, []byte(value))
			}
		}
	}
	dispatch()

	return mergeJSONEvents(events)
}

// eventPayloads returns the newline-joined form the stream format defines, or
// each field alone for streams that pack a whole object into every field.
func eventPayloads(fields [][]byte) [][]byte {
	if len(fields) < 2 {
		return fields
	}
	if joined := bytes.Join(fields, []byte("\n")); json.Valid(joined) {
		return [][]byte{joined}
	}
	return fields
}

func mergeJSONEvents(events [][]byte) ([]byte, error) {
	merged := make(map[string]interface{})
	for _, data := range events {
		var event map[string]interface{}
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		for k, v := range event {
			if k == "usage" && v != nil {
				if newMap, ok := v.(map[string]interface{}); ok {
					if existing, ok := merged[k].(map[string]interface{}); ok {
						for ek, ev := range newMap {
							existing[ek] = ev
						}
						continue
					}
				}
			}
			// A later null or blank must not erase what an earlier event supplied.
			// Azure's trailing filter chunks repeat "model" blank and "usage" null.
			if v == nil || v == "" {
				if _, exists := merged[k]; exists {
					continue
				}
			}
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return nil, fmt.Errorf("no valid JSON events found")
	}
	return json.Marshal(merged)
}
