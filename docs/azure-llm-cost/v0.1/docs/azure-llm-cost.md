---
title: "Overview"
---
# Azure LLM Cost

## Overview

This policy works out what each LLM call to **Azure OpenAI** or **Azure AI Foundry** costs, using the token counts Azure returns in the response and a pricing file shipped with the gateway.

It runs after the response comes back, so it never delays or blocks a request. If it cannot work out a price, the request still succeeds — it is simply recorded as unpriced.

Use this policy for Azure routes. For OpenAI, Anthropic, Gemini, Mistral, or AWS Bedrock use the [LLM Cost](../../llm-cost/v1.1/docs/llm-cost.md) policy instead. **Never attach both to the same route** — they write to the same place and would overwrite each other.

### Where the cost appears

| Where | Name | Value |
|---|---|---|
| Analytics events | `llmCost` | the cost in USD |
| `SharedContext.Metadata` | `x-llm-cost` | USD to 10 decimal places, e.g. `"0.0000423100"` |
| `SharedContext.Metadata` | `x-llm-cost-status` | `calculated` or `not_calculated` |

`x-llm-cost` is what downstream policies read — most usefully [LLM Cost Based Ratelimit](../../llm-cost-based-ratelimit/v1.0/docs/llm-cost-based-ratelimit.md), which enforces spending budgets.

The cost is **never returned to the caller** in a response header, so it stays internal to the gateway.

Check `x-llm-cost-status` rather than the amount: a cost of `0` could mean a genuinely free call or a failed calculation, and only the status tells you which.

## The one concept to understand: deployments vs models

Azure does not let you call a model directly. You create a **deployment** — your own name for an instance of a model:

```
deployment name : my-4o-mini          ← you chose this, it can be anything
model name      : gpt-4o-mini         ← what it actually runs, and what has a price
```

**The pricing file is keyed by model name.** So when Azure tells us only the deployment name, we cannot price the call without being told which model it runs. That is what `modelMappings` is for.

Which name Azure reports depends on the **endpoint**, not on whether you are using Azure OpenAI or Foundry:

| Endpoint | Azure reports | Needs a mapping? |
|---|---|---|
| `/chat/completions` (all forms) | the real model, e.g. `gpt-4.1-2025-04-14` | No |
| Foundry `/models/chat/completions` | the real model, e.g. `claude-opus-4-8` | No |
| `/openai/v1/responses` | the **deployment** name | **Yes** |
| `/openai/threads/.../runs` (assistants) | the **deployment** name | **Yes** |

The responses API simply echoes back the `model` you sent in the request, which is your deployment name — so there is nothing else in the response to price it by.

**Tip:** if you name a deployment exactly after its model (a deployment called `gpt-4o-mini`), every endpoint resolves it, mapping or not.

## Configuration

### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `modelMappings` | array | **Yes** | Your Azure deployments — the model each one runs, and its deployment type. |

Each entry describes one deployment:

| Field | Required | Default | Description |
|---|---|---|---|
| `deployment` | Yes | — | Your Azure deployment name, e.g. `my-4o-mini`. |
| `model` | Yes | — | The model it runs, e.g. `gpt-4o-mini`. |
| `region` | No | `global-standard` | Its deployment type, which sets the price tier. |

List **every deployment** the route can reach. A deployment you leave out will be unpriced on the endpoints that need a mapping.

### `region` — the deployment's price tier

Azure charges different rates depending on the deployment type you chose when you created the deployment. Because that is a **per-deployment** choice, `region` sits on each mapping entry rather than on the policy — two deployments in the same resource can be on different tiers.

| Value | Azure deployment type | What it means |
|---|---|---|
| `global-standard` *(default)* | Global Standard | Processed in any region. Azure's default. |
| `us` / `eu` / `apac` | Data Zone Standard | Processing stays in that data zone. |
| `regional` | Standard | Processing stays in one region. |

Provisioned (PTU) deployments are not listed: they bill reserved capacity by the hour, not per token, so a per-token calculator cannot represent them.

`region` has no effect on Azure AI Foundry's own models, which have no tier-based pricing.

### System parameter (set by the gateway admin in `config.toml`)

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pricing_file` | string | Yes | Path to the model pricing file shipped with the gateway. The `llm-cost` policy uses the same file. |

```toml
[policy_configurations.azure_llm_cost_v0]
pricing_file = "/etc/policy-engine/llm-pricing/model_prices.json"
```

In `gateway/build.yaml`, make sure the policy module is listed under `policies:`:

```yaml
- name: azure-llm-cost
  gomodule: github.com/wso2/gateway-controllers/policies/azure-llm-cost@v0
```

## Examples

### A single Azure OpenAI resource

```yaml
policies:
  - name: azure-llm-cost
    version: v0
    paths:
      - path: /openai/*
        methods: [POST]
        params:
          modelMappings:
            - deployment: apim-4o-mini
              model: gpt-4o-mini
            - deployment: prod-gpt5
              model: gpt-5.1
```

### Deployments on different price tiers

```yaml
params:
  modelMappings:
    - deployment: apim-4o-mini
      model: gpt-4o-mini
      region: eu              # a Data Zone deployment
    - deployment: prod-gpt5
      model: gpt-5.1          # region omitted, so Global Standard
```

### Azure AI Foundry

Nothing extra to set. One attachment covers a Foundry resource's own models *and* any OpenAI models it hosts — each is priced from the right catalog automatically.

```yaml
params:
  modelMappings:
    - deployment: my-llama
      model: Llama-3.3-70B-Instruct
    - deployment: apim-gpt-5.6-terra
      model: gpt-5.6-terra          # an OpenAI model hosted on Foundry
```

## How prices are looked up

Most users do not need this section. It matters if you maintain your own pricing file.

### Two catalogs

The pricing file holds two sets of keys:

```
azure/<model>          Azure OpenAI models
azure_ai/<model>       Azure AI Foundry's own models
```

A single Foundry resource can serve **both** — the OpenAI models it hosts are priced from `azure/`, its own models from `azure_ai/`. So the endpoint you connect to does not tell us which catalog applies, and there is no setting for it.

Both catalogs are always searched. The request path decides the order, which only matters for a model name that appears in both:

| Request path | Search order |
|---|---|
| contains `/openai/` | `azure/<region>/` → `azure/` → `azure_ai/` |
| anything else | `azure_ai/` → `azure/<region>/` → `azure/` |

### Model names must match exactly

There is no partial matching. A model your file does not carry is reported unpriced rather than billed at a similar model's rate — a deliberate choice, since `gpt-5.6-luna` and `gpt-5.6`, or `gpt-4o-mini` and `gpt-4o`, are very differently priced.

Two things follow:

- **New dated snapshots need their own keys.** Azure reports names like `gpt-4.1-2025-04-14`. When Azure ships a new one, add its key to your pricing file. Until then, those calls fall back to whatever model your mapping declares, and are unpriced if that is missing too.
- **The unprefixed `azure/<model>` key is the fallback for every tier.** Most entries in the shipped file are unprefixed and hold Global Standard rates. If a deployment declares `us`, `eu`, `apac`, or `regional` and the file has no key for that tier, the unprefixed rate is used and a warning is logged naming the key to add. The shipped file has no `apac` or `regional` keys at all.

## Troubleshooting

**The cost shows as 0 and `x-llm-cost-status` is `not_calculated`.** Check the gateway logs — the policy always says why:

| Log message | Cause | Fix |
|---|---|---|
| `model not found for costing` | The model has no key in the pricing file. The message lists the names that were tried. | Add a `modelMappings` entry for the deployment, or add the key to the pricing file. |
| `model has no per-token pricing` | The model is billed by another unit — image, embedding, rerank, speech. | Nothing to do; these cannot be priced per token. |
| `response has no usage data` | The response carried no token counts. | For streaming, request usage — for example `"stream_options": {"include_usage": true}`. |
| `no pricing entry for the configured tier` | A `region` was declared but the file has no key for it, so the base rate was used. | Add the `azure/<region>/<model>` key named in the message. |

**Costs look right but never appear in analytics.** The analytics field is `llmCost`. If it is `0` while the logs show a calculated cost, check that the policy is attached to the route actually serving the request.

## What is and is not counted

**Counted:** input and output tokens, cached input tokens at their discounted rate, Anthropic-style cache writes including the 1-hour tier, long-context and priority rates where the model has them, and streaming responses (priced once at the end of the stream).

**Not counted:** audio tokens are billed at the text rate, and image, character, per-second, web-search and code-interpreter charges are not applied. Models priced only by those units are reported unpriced.

## Notes

- The pricing file is read once at startup. **Restart the gateway** to pick up changes to it.
- `modelMappings` is per-attachment, so different routes can describe different deployments.
- The pricing file is yours to maintain — add, correct, or extend entries as your deployments change.
- The shipped file contains a few legacy `azure/global/...` keys. Azure has no deployment type called "Global", only Global Standard, so they duplicate the unprefixed keys and are never used. Prefer `azure/global-standard/...` if you add tier-specific entries.
