# Privacy Swap

A ZK-secure private swap program for Solana using Light Protocol compressed tokens and Pinocchio.

## Overview

Privacy Swap enables private token swaps by leveraging:

- **Light Protocol** - Compressed tokens with ZK proofs for privacy
- **Pinocchio** - Lightweight Solana program SDK for efficient on-chain execution
- **Meteora DAMM v2** - External DEX integration for swaps

## Flow

1. Decompress input tokens (Light Protocol - write mode)
2. Swap on external DEX (Meteora DAMM v2)
3. Compress output tokens (Light Protocol - execute mode)
4. Store encrypted audit log

## Building

```bash
cargo build-sbf
```

## Program ID

Devnet: `6Hf7GVAF8XizDn9xHoUJuv4RgaSTe1rJBNSe3cdzHWqa`

## License

MIT
