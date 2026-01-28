# Privacy Swap

A privacy-preserving swap protocol for Solana that breaks on-chain linkability between sender and receiver using Light Protocol's ZK compressed tokens.

## The Problem

Every transaction on Solana is permanently recorded and publicly visible. Sender, receiver, amount, timestamp - all traceable forever. Your financial history becomes an open book for anyone with a block explorer.

## The Solution

Privacy Swap severs the on-chain link between input and output through a decompress → swap → recompress flow:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Compressed     │     │   DEX Swap      │     │  Compressed     │
│  Token (Input)  │ ──► │  (Meteora)      │ ──► │  Token (Output) │
│                 │     │                 │     │                 │
│  ZK Proof       │     │  Program-owned  │     │  New Merkle     │
│  Decompress     │     │  temp accounts  │     │  Leaf (no link) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

The recompressed output creates a completely new leaf in the merkle tree with zero cryptographic link to the input leaf.

## How It Works

### Light Protocol Integration

The core privacy comes from Light Protocol's compressed token system:

**Decompress (requires ZK proof)**
- User provides a Groth16 proof (128 bytes) proving ownership of tokens at a merkle leaf
- Proof validates against Light Protocol's state tree without revealing which leaf
- Nullifier queue prevents double-spending
- Tokens convert from cToken → SPL

**Compress (no proof needed)**
- SPL tokens convert back to cTokens
- Creates fresh leaf in merkle tree
- No link to original input leaf

### Commitment Scheme

For the privacy pool pattern:

```
commitment = SHA256(secret || nonce)
```

- Commitment stored on-chain, but irreversible
- Claim link embeds secret + claim authority keypair
- Separate claim authority prevents front-running attacks

### Keeper Pattern

Two-step process for maximum unlinkability:

1. **Deposit** - User deposits, creates pending commitment
2. **Execute** - Keeper executes swap at arbitrary time
3. **Claim** - User claims with secret/nonce to any wallet

Timing between deposit and claim can be hours, days, or weeks - breaking temporal correlation.

## Features

- **Universal Privacy Pool** - Single vault accepts any SPL token, maximizing anonymity set
- **Fractional Claims** - Withdraw 25%, 50%, 75%, or 100% in separate transactions
- **ZK Proof Verification** - Groth16 proofs via Light Protocol
- **Merkle Tree State** - Compressed token state tracking with nullifier queue
- **DEX Integration** - Meteora DAMM v2 for swaps (more pools coming)
- **Claim Links** - Shareable URLs with embedded secrets
- **Timeout Refunds** - Reclaim deposits if keeper doesn't execute

## Architecture

```
program/
├── src/
│   ├── lib.rs              # Entrypoint
│   ├── processor.rs        # Instruction handlers
│   ├── instruction.rs      # Instruction definitions
│   ├── state.rs            # Account state (Pool, Commitment, Pending)
│   ├── light_cpi.rs        # Light Protocol CPI layer
│   ├── verification.rs     # Security checks
│   └── error.rs            # Custom errors
```

### Instructions

| Instruction | Description |
|-------------|-------------|
| `PRIVATE_SWAP` (V1) | Atomic decompress → swap → compress |
| `DEPOSIT_AND_SWAP` (V2) | Deposit with immediate swap |
| `DEPOSIT` (V3) | Create pending commitment |
| `EXECUTE_SWAP` (V3) | Keeper executes pending swap |
| `CLAIM` | Claim with secret/nonce proof |
| `DEPOSIT_DIRECT` (V4) | Same-token privacy transfer |
| `REFUND_PENDING` (V5) | Timeout-based refund |

### Account Layout (Private Swap)

```
0.  [signer] User wallet
1-2.  [] Input/Output token mints
3-4.  [] Temp SPL accounts (program-owned)
5-6.  [] Light Protocol SPL Interface PDAs
7.    [] CPI Authority PDA
8.    [] Light cToken Program
9.    [] SPL Token Program
10-11. [] Input Merkle tree + Nullifier queue
12-13. [] Output Merkle tree + Output queue
14-18. [] DEX pool accounts (Meteora)
```

## Tech Stack

- **Pinocchio SDK** - Anza's zero-dependency, `no_std` Solana SDK
  - Zero-copy abstractions with `AccountView`
  - Minimal compute unit usage
  - No supply chain risk
- **Light Protocol** - ZK compressed tokens
  - Transfer2 instruction (compress/decompress)
  - Merkle tree state management
  - Nullifier queue for double-spend prevention
- **Meteora DAMM v2** - DEX integration for swaps

## Building

```bash
# Build the program
cargo build-sbf

# Run tests
cargo test-sbf
```

## Deployment

```bash
# Deploy to devnet
solana program deploy target/deploy/privacy_swap.so --program-id <KEYPAIR>
```

## Program IDs

| Network | Address |
|---------|---------|
| Devnet | `6Hf7GVAF8XizDn9xHoUJuv4RgaSTe1rJBNSe3cdzHWqa` |
| Mainnet | TBD |

## Security

- CPI program ID verification
- Safe fee calculations (u128 intermediate to prevent overflow)
- Distinct account checks (prevent same account reuse)
- Claim authority separation (prevents front-running)
- Timeout-based refunds (keeper failure protection)
- Minimum fee enforcement (prevents fee bypass)

## Roadmap

- [ ] Integration with Raydium, Orca, Jupiter
- [ ] Privacy-native AMM (no decompress cycle)
- [ ] More deposit tiers
- [ ] Improved keeper network
- [ ] Mobile support
- [ ] Hardware wallet integration

## License

MIT

---

Built by [@infraboy](https://github.com/infraboy) | Part of [uranus.exchange](https://uranus.exchange)
