# 🛡️ ShieldAgent — AI-Powered DeFi Security Sentinel

> Autonomous smart contract vulnerability scanner. 24/7 protection. Built on [EvoClaw](https://github.com/clawinfra/evoclaw) + [ClawChain](https://github.com/clawinfra/clawchain).

[![CI](https://github.com/clawinfra/shield-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/clawinfra/shield-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Powered by EvoClaw](https://img.shields.io/badge/Powered%20by-EvoClaw-blue)](https://github.com/clawinfra/evoclaw)

<p align="center">
  <img src="assets/shield_agent_hero.png" alt="ShieldAgent — AI-Powered DeFi Security Sentinel" width="600"/>
</p>

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

## On-Chain Audit Attestation

Every ShieldAgent scan can be attested on ClawChain via `pallet-agent-receipts`:

1. **Scan completes** → `ScanResult` produced with vulnerabilities, risk score, timestamp
2. **SHA-256 hash** computed from `(address, risk_score, vuln_count, timestamp)`
3. **`submit_receipt()`** called on ClawChain testnet → immutable on-chain proof
4. **Verifiable record**: "ShieldAgent scanned contract X at time T and found Y"

```bash
# Run demo scan with ClawChain attestation
python -m shield_agent.poc_scan --demo --attest

# Output includes:
# [ClawChain] Attesting scan: 0xDEMO_REE...
# [ClawChain] Input hash:  0x53950a5fa393baa0...
# [ClawChain] Output hash: 0x34e1db26095148a6...
# [ClawChain] RPC: wss://testnet.clawchain.win
```

Auditors, insurers, and DAOs can verify any scan result on-chain.

**Status:** Stub mode (hashes computed locally). Full RPC integration pending `substrate-interface` + ClawChain testnet account.

ClawChain explorer: https://testnet.clawchain.win

## Demo Mode

ShieldAgent includes built-in demo contracts with known vulnerabilities for testing:

```bash
# Scan demo contracts (no network required)
python -m shield_agent.poc_scan --demo

# Scan real DeFi contracts (dry run — no API calls)
python -m shield_agent.poc_scan --dry-run

# Full scan with attestation
python -m shield_agent.poc_scan --demo --attest
```

## Source Fetching

ShieldAgent uses a multi-provider fallback strategy for source code:

1. **Etherscan API** — works with or without API key (rate-limited without)
2. **Sourcify** — public verified source repo, no key required
3. **Graceful failure** — returns `source_available=False` if both fail

## Roadmap

| Version | Milestone | Status |
|---------|-----------|--------|
| **v0.1** | PoC scanner — static analysis + pattern matching + multi-source fetching | ✅ Done |
| **v0.2** | Live monitoring — continuous on-chain watching | ⏳ Planned |
| **v0.3** | ClawChain attestation — on-chain audit receipts (stub wired) | 🚧 In Progress |
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
