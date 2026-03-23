> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [Secretless](https://github.com/opena2a-org/secretless-ai) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [ABG](https://github.com/opena2a-org/AI-BrowserGuard) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [ARP](https://github.com/opena2a-org/hackmyagent#agent-runtime-protection) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

# arp-guard — Agent Runtime Protection

[![npm](https://img.shields.io/npm/v/arp-guard)](https://www.npmjs.com/package/arp-guard)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OASB](https://img.shields.io/badge/OASB-222%20tests%20passing-brightgreen)](https://github.com/opena2a-org/oasb)

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

Detects prompt injection, jailbreaks, data exfiltration, MCP exploitation, and A2A identity spoofing across 19 pattern categories.

## Intelligence Stack

| Layer | Cost | Coverage |
|-------|------|----------|
| L0: Rules | Free | Pattern matching on every event |
| L1: Statistical | Free | Z-score anomaly detection |
| L2: LLM-Assisted | Budget-controlled | Micro-prompts for ambiguous events |

99% of events resolve at L0/L1. Default L2 budget: $5/month.

## Architecture

This package re-exports ARP from [HackMyAgent](https://github.com/opena2a-org/hackmyagent). All implementation lives in `hackmyagent/src/arp/`. Use this package when you want ARP as a standalone dependency without importing HackMyAgent directly.

## Benchmark

Evaluated by [OASB](https://github.com/opena2a-org/oasb) — 222 standardized attack scenarios mapped to MITRE ATLAS. 100% detection coverage on the current test suite.

## License

Apache-2.0
