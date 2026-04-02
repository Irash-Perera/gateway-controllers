---
title: "Overview"
---
# Set Status Code

## Overview

The Set Status Code policy overwrites the HTTP status code of the upstream response
before it is forwarded to the downstream client. This is useful for normalising status
codes across backends or masking upstream error codes from clients.

## Features

- Overwrite the upstream response status code with any valid HTTP status code (100–599)
- Simple single-parameter configuration (`statusCode`)
- Validates that the provided status code is within the allowed range

## Configuration

This policy expects a single parameter `statusCode` (integer) that specifies the HTTP
status code to set on the response.

### User Parameters (API Definition)

| Parameter    | Type    | Required | Description |
|--------------|---------|----------|-------------|
| `statusCode` | integer | Yes      | The HTTP status code to set on the upstream response. Must be between 100 and 599. |

### Sample policy params

```yaml
- name: set-status-code
  version: v0.1
  params:
    statusCode: 200
```

## Example API snippet

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: example-api
spec:
  displayName: Example API
  version: v1
  context: /example/$version
  upstream:
    main:
      url: http://example-backend:8080
  policies:
    - name: set-status-code
      version: v0.1
      params:
        statusCode: 200
```

## How it works

- At response body processing, the policy validates the `statusCode` parameter.
- If valid, it returns a `DownstreamResponseModifications` action with `StatusCode`
  set to the configured value. The kernel applies this before forwarding the response
  to the client. The response body and headers are passed through unchanged.
- If configuration is invalid (missing, wrong type, or out of range), the policy
  returns an immediate 500 configuration error response.

## Notes

- Only the status code is modified; the response body and headers are forwarded as-is.
- The status code must be a valid HTTP status code integer between 100 and 599.
