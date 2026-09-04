> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [Secretless](https://github.com/opena2a-org/secretless-ai) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [ABG](https://github.com/opena2a-org/AI-BrowserGuard) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [ARP](https://github.com/opena2a-org/agent-runtime-protection) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

# arp-guard — Agent Runtime Protection

[![Status: beta](https://img.shields.io/badge/status-beta-yellow)](./STATUS.md)
[![npm](https://img.shields.io/npm/v/arp-guard)](https://www.npmjs.com/package/arp-guard)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OASB](https://img.shields.io/badge/OASB-reference%20adapter-blue)](https://github.com/opena2a-org/oasb)

3-layer intelligent runtime protection for AI agents. Monitors processes, network, filesystem, and AI-layer communications (prompts, MCP tool calls, A2A messages) with rule-based, statistical, and LLM-assisted threat detection.

## Install

```bash
npm install arp-guard
```

## Quick Start

```typescript
import { AgentRuntimeProtection } from 'arp-guard';

const arp = new AgentRuntimeProtection({ agentName: 'my-agent' });
await arp.start();

// Agent runs normally — ARP monitors in background
// Process spawns, network connections, file access, prompts all monitored

await arp.stop();
```

## AI-Layer Scanning

```typescript
import { scanText, ALL_PATTERNS } from 'arp-guard';

const result = scanText(userInput, ALL_PATTERNS);
if (result.detected) {
  console.log('Threats found:', result.matches.map(m => m.pattern.id));
}
```

Detects prompt injection, jailbreaks, data exfiltration, MCP exploitation, and A2A identity spoofing across 20 patterns in 7 categories.

## Intelligence Stack

| Layer | Cost | Coverage |
|-------|------|----------|
| L0: Rules | Free | Pattern matching on every event |
| L1: Statistical | Free | Z-score anomaly detection |
| L2: LLM-Assisted | Budget-controlled | Micro-prompts for ambiguous events |

L2 runs only when L1 flags an event, its severity is at or above
`intelligence.minSeverityForLlm` (default `medium`), and the budget allows it. Default
budget: $5/month (`intelligence.budgetUsd`).

L2 is on by default, and the default adapter picks its destination from the environment:
`ANTHROPIC_API_KEY` if set, otherwise `OPENAI_API_KEY`, otherwise a local Ollama at
`localhost:11434`. On a machine that already exports a model key, qualifying events are
sent to that vendor with the agent context and the event, which for a process event
includes the command line. Set `intelligence.enabled: false` to run on L0 and L1 alone
with no outbound calls, or `intelligence.adapter: ollama` to keep inference local.

## Architecture

The runtime engine lives in the AIM agent-side SDK, at `@opena2a/aim-sdk/arp`. The
product boundary is by time: scan at rest with HackMyAgent, protect at runtime with ARP.

This package re-exports that module directly, on an exact SDK pin, so installing
`arp-guard` no longer pulls in the scanner or its model runtime. Importing
`@opena2a/aim-sdk/arp` yourself gets you the same engine; use this package when you want
ARP as a standalone dependency.

## Benchmark

[OASB](https://github.com/opena2a-org/oasb) is a suite of 222 standardized attack scenarios
mapped to MITRE ATLAS, and it ships ARP as its reference adapter.

Two caveats on that number, both verifiable from a clean checkout:

- OASB's own suite skips `E2E-003` (live network detection) pending a reliable
  cross-platform check, so network detection is not covered by the passing count.
- The suite resolves ARP through an older `hackmyagent` that carries its own
  pre-migration copy of the runtime engine. Re-point it at `@opena2a/aim-sdk/arp`
  before reading the result as coverage of what this package ships today.

## License

Apache-2.0
