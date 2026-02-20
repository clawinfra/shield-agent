# 🛡️ ShieldAgent — AI-Powered DeFi Security Sentinel

> Autonomous smart contract vulnerability scanner. 24/7 protection. Built on [EvoClaw](https://github.com/clawinfra/evoclaw) + [ClawChain](https://github.com/clawinfra/clawchain).

[![CI](https://github.com/clawinfra/shield-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/clawinfra/shield-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Powered by EvoClaw](https://img.shields.io/badge/Powered%20by-EvoClaw-blue)](https://github.com/clawinfra/evoclaw)

---

## What is ShieldAgent?

ShieldAgent is an AI agent that **continuously monitors smart contracts for exploitable vulnerabilities**. Every audit result is attested on-chain via ClawChain's `pallet-agent-receipts` (ProvenanceChain).

Think **Immunefi + Forta + AI**, running autonomously.

- 🔍 **Static analysis** of deployed contract source code
- 🧬 **Pattern matching** against known exploit signatures
- 📜 **On-chain attestation** — every scan result is a provable, immutable receipt
- 🚨 **Real-time alerts** via Telegram and Discord

## Why Now?

| Signal | Data |
|--------|------|
| AI outperforms humans | Cecuro benchmark: specialized AI catches **3× more exploits** than GPT-4 |
| Offensive AI is accelerating | Attack tooling capabilities doubling every **1.3 months** |
| DeFi losses are staggering | **$2B+** lost to DeFi exploits in 2024 alone |
| Coverage gap | Every protocol with >$1M TVL needs 24/7 monitoring — most don't have it |

The window between "vulnerability discovered" and "exploit executed" is shrinking. Autonomous, always-on security isn't optional anymore.

## Architecture

```
Smart Contract → ShieldAgent Scanner → Vulnerability Report
                        ↓
                 EvoClaw Runtime (orchestration)
                        ↓
                 ClawChain pallet-agent-receipts (on-chain audit proof)
                        ↓
                 Alert → Protocol Team / Bug Bounty
```

## Features

- **Static Analysis** — Pattern-based vulnerability detection across Solidity source code
- **Known Exploit Signatures** — Checks against reentrancy, flash loan, oracle manipulation, access control, and overflow patterns
- **Risk Scoring** — 0–100 score with LOW / MEDIUM / HIGH / CRITICAL classification
- **On-Chain Attestation** — Scan results recorded via ClawChain's `pallet-agent-receipts`
- **Alerting** — Telegram and Discord notifications for high-severity findings
- **PoC Scanner** — Pre-configured scan of top 10 most-forked DeFi contracts

## Quick Start

```bash
# Install
pip install shield-agent

# Scan a contract
shield-agent scan 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --network mainnet

# Continuous monitoring (every hour)
shield-agent monitor 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --interval 3600

# Get a scan report
shield-agent report <scan_id>
```

## Vulnerability Coverage

| Category | Description | Severity |
|----------|-------------|----------|
| **Reentrancy** | External calls before state changes | CRITICAL |
| **Flash Loan Attacks** | Unchecked flash loan callback patterns | HIGH |
| **Price Oracle Manipulation** | Single-source oracle dependencies | HIGH |
| **Access Control Bypass** | Missing `onlyOwner`, `tx.origin` usage | CRITICAL |
| **Integer Overflow** | Unchecked arithmetic (pre-0.8.0) | MEDIUM |

## Roadmap

| Version | Milestone | Status |
|---------|-----------|--------|
| **v0.1** | PoC scanner — static analysis + pattern matching | 🚧 In Progress |
| **v0.2** | Live monitoring — continuous on-chain watching | ⏳ Planned |
| **v0.3** | ClawChain attestation — on-chain audit receipts | ⏳ Planned |
| **v1.0** | Protection-as-a-Service — managed security for protocols | ⏳ Planned |

## Built With

- **Python 3.11+** — Core runtime
- **[EvoClaw](https://github.com/clawinfra/evoclaw)** — Agent orchestration
- **[ClawChain](https://github.com/clawinfra/clawchain)** — On-chain attestation (Substrate)
- **[Slither](https://github.com/crytic/slither)** — Solidity static analysis
- **[web3.py](https://github.com/ethereum/web3.py)** — Ethereum interaction
- **[Rich](https://github.com/Textualize/rich)** — Terminal output

## License

[MIT](LICENSE)
