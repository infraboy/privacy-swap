//! Program instructions
//!
//! V2 adds privacy pool instructions with commitment scheme.

use alloc::vec::Vec;
use pinocchio::Address;

/// Instruction discriminators
pub mod discriminator {
    // V1 instructions (legacy)
    pub const PRIVATE_SWAP: u8 = 0;
    pub const INITIALIZE_CONFIG: u8 = 1;
    pub const UPDATE_OWNER_KEY: u8 = 2;
    pub const CLOSE_ACCOUNTS: u8 = 3;

    // V2 instructions (privacy pools - atomic swap)
    pub const INITIALIZE_POOL: u8 = 10;
    pub const DEPOSIT_AND_SWAP: u8 = 11;  // Legacy: atomic deposit+swap
    pub const CLAIM: u8 = 12;
    pub const EXPAND_NULLIFIER: u8 = 15;

    // V3 instructions (Keeper pattern - full privacy with any DEX)
    /// Deposit tokens to vault (no swap yet) - creates Pending commitment
    pub const DEPOSIT: u8 = 16;
    /// Keeper executes swap within vault - marks commitment as Swapped
    pub const EXECUTE_SWAP: u8 = 17;

    // V4 instruction (Direct transfer - no swap needed)
    /// Direct deposit for same-token transfers - immediately claimable
    /// No swap step, no keeper needed. Pure privacy transfer.
    pub const DEPOSIT_DIRECT: u8 = 18;

    // V5 instruction (HIGH-002 fix: Refund mechanism)
    /// Refund pending deposit if keeper hasn't swapped within timeout
    /// Requires proof of knowledge (secret/nonce) to claim refund
    pub const REFUND_PENDING: u8 = 19;
}

// ============================================================
// V2 INSTRUCTION ARGS
// ============================================================

/// Initialize a new privacy pool
///
/// Creates vault PDAs, token accounts, and pool config for a
/// specific (input_mint, output_mint, tier) combination.
///
/// NOTE: Client must derive the PDA bumps off-chain and pass them here.
#[derive(Debug, Clone)]
pub struct InitializePoolArgs {
    /// Denomination tier (0-7)
    pub tier: u8,
    /// DEX type to use for swaps
    pub dex_type: u8,
    /// Vault PDA bump (derived by client)
    pub vault_bump: u8,
    /// Pool config PDA bump (derived by client)
    pub pool_config_bump: u8,
    /// Nullifier registry PDA bump (derived by client)
    pub nullifier_bump: u8,
    /// DEX pool address
    pub dex_pool: Address,
}

impl InitializePoolArgs {
    // discriminator(1) + tier(1) + dex_type(1) + bumps(3) + dex_pool(32) = 38
    pub const SIZE: usize = 1 + 1 + 1 + 3 + 32;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            tier: data[1],
            dex_type: data[2],
            vault_bump: data[3],
            pool_config_bump: data[4],
            nullifier_bump: data[5],
            dex_pool: Address::new_from_array(data[6..38].try_into().ok()?),
        })
    }
}

/// Deposit tokens and swap atomically
///
/// User provides:
/// - commitment: hash(secret || nonce) - computed client-side
/// - commitment_bump: PDA bump for commitment account (derived by client)
/// - min_output_amount: slippage protection
///
/// Program does:
/// 1. Transfer user's SPL tokens to vault
/// 2. Swap on DEX (vault signs)
/// 3. Create commitment account with output amount
#[derive(Debug, Clone)]
pub struct DepositAndSwapArgs {
    /// Commitment hash = hash(secret || nonce)
    /// User generates secret client-side, keeps it safe
    pub commitment: [u8; 32],
    /// Commitment PDA bump (derived by client)
    pub commitment_bump: u8,
    /// Minimum output amount (slippage protection)
    pub min_output_amount: u64,
}

impl DepositAndSwapArgs {
    // discriminator(1) + commitment(32) + commitment_bump(1) + min_output(8) = 42
    pub const SIZE: usize = 1 + 32 + 1 + 8;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let commitment: [u8; 32] = data[1..33].try_into().ok()?;
        let commitment_bump = data[33];
        let min_output_amount = u64::from_le_bytes(data[34..42].try_into().ok()?);

        Some(Self {
            commitment,
            commitment_bump,
            min_output_amount,
        })
    }
}

/// Claim swapped tokens using secret (V4 with fractional claims)
///
/// User provides:
/// - secret: The random value they generated during deposit
/// - nonce: Additional entropy used in commitment
/// - destination: Where to send the tokens (any address!)
/// - claim_percentage: How much to claim (25, 50, 75, or 100)
///
/// Program verifies:
/// - hash(secret || nonce) == stored commitment
/// - Commitment is in Swapped or PartialClaim status
/// - claim_percentage is valid (25, 50, 75, or 100)
///
/// Fractional Claims:
/// - 100%: Full claim, commitment nullified
/// - 25/50/75%: Partial claim, remainder stays for future claims
/// - Enhances privacy by breaking amount correlation
#[derive(Debug, Clone)]
pub struct ClaimArgs {
    /// The secret generated during deposit
    pub secret: [u8; 32],
    /// Nonce used in commitment
    pub nonce: u64,
    /// Destination address for tokens (can be ANY address)
    pub destination: Address,
    /// Claim percentage (25, 50, 75, or 100)
    /// Using fixed tiers for larger anonymity sets
    pub claim_percentage: u8,
}

impl ClaimArgs {
    // discriminator(1) + secret(32) + nonce(8) + destination(32) + claim_percentage(1) = 74
    pub const SIZE: usize = 1 + 32 + 8 + 32 + 1;

    /// Valid claim percentages (fixed tiers for privacy)
    pub const VALID_PERCENTAGES: [u8; 4] = [25, 50, 75, 100];

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let secret: [u8; 32] = data[1..33].try_into().ok()?;
        let nonce = u64::from_le_bytes(data[33..41].try_into().ok()?);
        let destination = Address::new_from_array(data[41..73].try_into().ok()?);
        let claim_percentage = data[73];

        Some(Self {
            secret,
            nonce,
            destination,
            claim_percentage,
        })
    }

    /// Validate that claim_percentage is one of the allowed values
    pub fn is_valid_percentage(&self) -> bool {
        Self::VALID_PERCENTAGES.contains(&self.claim_percentage)
    }
}

/// Expand nullifier registry when it's nearly full
/// Creates a new, larger registry and migrates data
#[derive(Debug, Clone)]
pub struct ExpandNullifierArgs {
    /// New capacity (must be larger than current)
    pub new_capacity: u32,
}

impl ExpandNullifierArgs {
    pub const SIZE: usize = 1 + 4;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let new_capacity = u32::from_le_bytes(data[1..5].try_into().ok()?);

        Some(Self { new_capacity })
    }
}

// ============================================================
// V3 INSTRUCTION ARGS (Keeper Pattern)
// ============================================================

/// Deposit tokens to vault (Keeper pattern - Step 1)
///
/// User deposits INPUT tokens to vault. No swap happens yet.
/// Creates a commitment account with status = Pending.
/// Keeper will later call EXECUTE_SWAP to swap within vault.
///
/// Privacy: User only interacts with vault PDA, not DEX directly.
///
/// CRIT-007 FIX: claim_authority prevents front-running attacks.
/// User generates a fresh keypair and stores claim_authority pubkey.
/// Only a signature from claim_authority's private key can claim.
///
/// HIGH-003 FIX: user_min_output prevents keeper from setting low slippage.
/// User specifies minimum acceptable output. Keeper's min_output_amount
/// MUST be >= this value, preventing value extraction attacks.
#[derive(Debug, Clone)]
pub struct DepositArgs {
    /// Commitment hash = hash(secret || nonce)
    /// User generates secret client-side, keeps it safe
    pub commitment: [u8; 32],
    /// Commitment PDA bump (derived by client)
    pub commitment_bump: u8,
    /// Amount of input tokens to deposit
    pub input_amount: u64,
    /// HIGH-003 FIX: User's minimum output amount (slippage protection)
    /// Keeper's min_output_amount MUST be >= this value
    pub user_min_output: u64,
    /// CRIT-007 FIX: Claim authority pubkey (anti-frontrunning)
    /// Only this pubkey can sign claim transactions
    /// User generates fresh keypair, shares private key with recipient off-chain
    pub claim_authority: Address,
}

impl DepositArgs {
    // discriminator(1) + commitment(32) + commitment_bump(1) + input_amount(8) + user_min_output(8) + claim_authority(32) = 82
    pub const SIZE: usize = 1 + 32 + 1 + 8 + 8 + 32;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let commitment: [u8; 32] = data[1..33].try_into().ok()?;
        let commitment_bump = data[33];
        let input_amount = u64::from_le_bytes(data[34..42].try_into().ok()?);
        let user_min_output = u64::from_le_bytes(data[42..50].try_into().ok()?);
        let claim_authority = Address::new_from_array(data[50..82].try_into().ok()?);

        Some(Self {
            commitment,
            commitment_bump,
            input_amount,
            user_min_output,
            claim_authority,
        })
    }
}

/// Execute swap within vault (Keeper pattern - Step 2)
///
/// Keeper calls this to swap tokens inside the vault.
/// Takes Pending commitments and swaps input -> output.
/// Marks commitment as Swapped with output_amount recorded.
///
/// Privacy: Swap happens inside vault, not linked to depositor.
/// Flexibility: Keeper can use ANY DEX via swap-api routing.
#[derive(Debug, Clone)]
pub struct ExecuteSwapArgs {
    /// Commitment hash to process (must be in Pending status)
    pub commitment: [u8; 32],
    /// Minimum output amount (slippage protection)
    pub min_output_amount: u64,
    /// DEX type used (for record-keeping)
    pub dex_type: u8,
}

impl ExecuteSwapArgs {
    // discriminator(1) + commitment(32) + min_output(8) + dex_type(1) = 42
    pub const SIZE: usize = 1 + 32 + 8 + 1;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let commitment: [u8; 32] = data[1..33].try_into().ok()?;
        let min_output_amount = u64::from_le_bytes(data[33..41].try_into().ok()?);
        let dex_type = data[41];

        Some(Self {
            commitment,
            min_output_amount,
            dex_type,
        })
    }
}

// ============================================================
// V4 INSTRUCTION ARGS (Direct Transfer - No Swap)
// ============================================================

/// Direct deposit for privacy transfers (no swap needed)
///
/// User deposits tokens directly to vault, immediately claimable.
/// No keeper, no swap step. Pure privacy transfer protocol.
///
/// Use case: Private transfers of the SAME token
/// - Deposit USDC → Claim USDC from fresh wallet
/// - Deposit SOL → Claim SOL from fresh wallet
///
/// CRIT-007 FIX: claim_authority prevents front-running attacks.
#[derive(Debug, Clone)]
pub struct DepositDirectArgs {
    /// Commitment hash = hash(secret || nonce)
    pub commitment: [u8; 32],
    /// Commitment PDA bump (derived by client)
    pub commitment_bump: u8,
    /// Amount of tokens to deposit (= amount to claim)
    pub amount: u64,
    /// CRIT-007 FIX: Claim authority pubkey (anti-frontrunning)
    /// Only this pubkey can sign claim transactions
    pub claim_authority: Address,
}

impl DepositDirectArgs {
    // discriminator(1) + commitment(32) + commitment_bump(1) + amount(8) + claim_authority(32) = 74
    pub const SIZE: usize = 1 + 32 + 1 + 8 + 32;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let commitment: [u8; 32] = data[1..33].try_into().ok()?;
        let commitment_bump = data[33];
        let amount = u64::from_le_bytes(data[34..42].try_into().ok()?);
        let claim_authority = Address::new_from_array(data[42..74].try_into().ok()?);

        Some(Self {
            commitment,
            commitment_bump,
            amount,
            claim_authority,
        })
    }
}

// ============================================================
// V1 INSTRUCTION TYPES (Legacy)
// ============================================================

/// Supported DEX types for swapping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DexType {
    /// Meteora DAMM v2 (constant product)
    MeteoraDammV2 = 0,
    /// Meteora DLMM (concentrated liquidity)
    MeteoraDlmm = 1,
    /// Orca Whirlpool
    OrcaWhirlpool = 2,
    /// Raydium CLMM
    RaydiumClmm = 3,
}

impl TryFrom<u8> for DexType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DexType::MeteoraDammV2),
            1 => Ok(DexType::MeteoraDlmm),
            2 => Ok(DexType::OrcaWhirlpool),
            3 => Ok(DexType::RaydiumClmm),
            _ => Err(()),
        }
    }
}

// ============================================================
// V5 INSTRUCTION ARGS (HIGH-002 FIX: Refund Mechanism)
// ============================================================

/// Refund pending deposit (HIGH-002 fix)
///
/// Allows users to recover funds if keeper hasn't executed swap
/// within REFUND_TIMEOUT_SLOTS (default: 1000 slots ~ 7 minutes).
///
/// Requires proof of knowledge (secret/nonce) to prevent theft.
#[derive(Debug, Clone)]
pub struct RefundPendingArgs {
    /// The secret generated during deposit (proves ownership)
    pub secret: [u8; 32],
    /// Nonce used in commitment
    pub nonce: u64,
}

impl RefundPendingArgs {
    // discriminator(1) + secret(32) + nonce(8) = 41
    pub const SIZE: usize = 1 + 32 + 8;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let secret: [u8; 32] = data[1..33].try_into().ok()?;
        let nonce = u64::from_le_bytes(data[33..41].try_into().ok()?);

        Some(Self { secret, nonce })
    }
}

/// Compressed ZK validity proof from Light Protocol indexer
/// Required for decompress operations to prove ownership
#[derive(Debug, Clone)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl CompressedProof {
    /// Total size: 32 + 64 + 32 = 128 bytes
    pub const SIZE: usize = 128;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let a: [u8; 32] = data[0..32].try_into().ok()?;
        let b: [u8; 64] = data[32..96].try_into().ok()?;
        let c: [u8; 32] = data[96..128].try_into().ok()?;
        Some(Self { a, b, c })
    }
}

/// Merkle context for compressed token account
/// Contains indices needed for the ZK proof verification
#[derive(Debug, Clone)]
pub struct MerkleContext {
    /// Root index in the state tree
    pub root_index: u16,
    /// Leaf index (nullifier derived from this)
    pub leaf_index: u32,
    /// Merkle tree index in packed accounts
    pub merkle_tree_index: u8,
    /// Queue account index in packed accounts
    pub queue_index: u8,
}

impl MerkleContext {
    /// Size: 2 + 4 + 1 + 1 = 8 bytes
    pub const SIZE: usize = 8;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            root_index: u16::from_le_bytes(data[0..2].try_into().ok()?),
            leaf_index: u32::from_le_bytes(data[2..6].try_into().ok()?),
            merkle_tree_index: data[6],
            queue_index: data[7],
        })
    }
}

/// Private swap instruction data
///
/// Format (total ~157+ bytes):
/// - discriminator: 1 byte
/// - input_amount: 8 bytes
/// - min_output_amount: 8 bytes
/// - proof: 128 bytes (CompressedProof)
/// - merkle_context: 8 bytes (MerkleContext)
/// - input_pool_bump: 1 byte
/// - input_pool_index: 1 byte
/// - output_pool_bump: 1 byte
/// - output_pool_index: 1 byte
/// - dex_type: 1 byte
/// - encrypted_audit_len: 2 bytes
/// - encrypted_audit: variable
#[derive(Debug, Clone)]
pub struct PrivateSwapArgs {
    /// Amount of input tokens
    pub input_amount: u64,
    /// Minimum output amount (slippage protection)
    pub min_output_amount: u64,
    /// ZK validity proof for decompress (from Light Protocol indexer)
    pub proof: CompressedProof,
    /// Merkle context for the compressed input token account
    pub merkle_context: MerkleContext,
    /// Light Protocol SPL interface PDA bump for input token
    pub input_spl_interface_bump: u8,
    /// Light Protocol pool index for input token
    pub input_pool_index: u8,
    /// Light Protocol SPL interface PDA bump for output token
    pub output_spl_interface_bump: u8,
    /// Light Protocol pool index for output token
    pub output_pool_index: u8,
    /// DEX to use for swap
    pub dex_type: DexType,
    /// Encrypted audit data
    /// Format: [ephemeral_pubkey(32) | nonce(12) | ciphertext_len(4) | ciphertext]
    pub encrypted_audit: Vec<u8>,
}

impl PrivateSwapArgs {
    /// Minimum data size without audit: 1 + 8 + 8 + 128 + 8 + 4 + 1 + 2 = 160 bytes
    pub const MIN_SIZE: usize = 160;

    pub fn unpack(data: &[u8]) -> Option<Self> {
        // Format:
        // [0]: discriminator (1 byte)
        // [1-8]: input_amount (8 bytes, little-endian)
        // [9-16]: min_output_amount (8 bytes, little-endian)
        // [17-144]: proof (128 bytes: a[32] + b[64] + c[32])
        // [145-152]: merkle_context (8 bytes)
        // [153]: input_spl_interface_bump (1 byte)
        // [154]: input_pool_index (1 byte)
        // [155]: output_spl_interface_bump (1 byte)
        // [156]: output_pool_index (1 byte)
        // [157]: dex_type (1 byte)
        // [158-159]: encrypted_audit_len (2 bytes, little-endian)
        // [160..]: encrypted_audit (variable)

        if data.len() < Self::MIN_SIZE {
            return None;
        }

        let input_amount = u64::from_le_bytes(data[1..9].try_into().ok()?);
        let min_output_amount = u64::from_le_bytes(data[9..17].try_into().ok()?);
        let proof = CompressedProof::unpack(&data[17..145])?;
        let merkle_context = MerkleContext::unpack(&data[145..153])?;
        let input_spl_interface_bump = data[153];
        let input_pool_index = data[154];
        let output_spl_interface_bump = data[155];
        let output_pool_index = data[156];
        let dex_type = DexType::try_from(data[157]).ok()?;
        let audit_len = u16::from_le_bytes(data[158..160].try_into().ok()?) as usize;

        if data.len() < Self::MIN_SIZE + audit_len {
            return None;
        }

        let encrypted_audit = data[160..160 + audit_len].to_vec();

        Some(Self {
            input_amount,
            min_output_amount,
            proof,
            merkle_context,
            input_spl_interface_bump,
            input_pool_index,
            output_spl_interface_bump,
            output_pool_index,
            dex_type,
            encrypted_audit,
        })
    }
}

/// Initialize config instruction data
#[derive(Debug, Clone)]
pub struct InitializeConfigArgs {
    /// Owner's encryption public key for audit logs (32 bytes X25519)
    pub owner_encryption_pubkey: [u8; 32],
}

impl InitializeConfigArgs {
    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }

        let owner_encryption_pubkey: [u8; 32] = data[1..33].try_into().ok()?;

        Some(Self {
            owner_encryption_pubkey,
        })
    }
}

/// Close accounts instruction - returns rent to specified address
#[derive(Debug, Clone)]
pub struct CloseAccountsArgs {
    /// Address to receive reclaimed rent
    pub rent_destination: Address,
}

impl CloseAccountsArgs {
    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }

        let rent_destination = Address::new_from_array(data[1..33].try_into().ok()?);

        Some(Self {
            rent_destination,
        })
    }
}
