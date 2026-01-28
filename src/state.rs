//! Program state accounts
//!
//! V2 adds privacy pools with commitment scheme for true unlinkability.

use pinocchio::Address;

// ============================================================
// V2 STATE: PRIVACY POOLS WITH COMMITMENTS
// ============================================================

/// Commitment status for Keeper pattern
/// Tracks the lifecycle: Pending -> Swapped -> PartialClaim/FullyClaimed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommitmentStatus {
    /// Tokens deposited, waiting for keeper to execute swap
    Pending = 0,
    /// Keeper has executed swap, tokens ready for claim
    Swapped = 1,
    /// Some tokens claimed, more remaining (partial withdrawal)
    PartialClaim = 2,
    /// All tokens claimed, commitment nullified
    FullyClaimed = 3,
}

impl CommitmentStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(CommitmentStatus::Pending),
            1 => Some(CommitmentStatus::Swapped),
            2 => Some(CommitmentStatus::PartialClaim),
            3 => Some(CommitmentStatus::FullyClaimed),
            _ => None,
        }
    }
}

/// Denomination tier for privacy pools
/// Each tier has its own anonymity set
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DenominationTier {
    Micro = 0,   // 0.001 SOL / $0.10
    Mini = 1,    // 0.01 SOL / $1
    Small = 2,   // 0.1 SOL / $10
    Medium = 3,  // 1 SOL / $100
    Large = 4,   // 10 SOL / $1,000
    XLarge = 5,  // 100 SOL / $10,000
    XXLarge = 6, // 1,000 SOL / $100,000
    Max = 7,     // 10,000 SOL / $1,000,000
}

impl DenominationTier {
    /// Get the SOL amount for this tier (in lamports)
    pub fn sol_amount(&self) -> u64 {
        match self {
            DenominationTier::Micro => 1_000_000,        // 0.001 SOL
            DenominationTier::Mini => 10_000_000,       // 0.01 SOL
            DenominationTier::Small => 100_000_000,     // 0.1 SOL
            DenominationTier::Medium => 1_000_000_000,  // 1 SOL
            DenominationTier::Large => 10_000_000_000,  // 10 SOL
            DenominationTier::XLarge => 100_000_000_000, // 100 SOL
            DenominationTier::XXLarge => 1_000_000_000_000, // 1,000 SOL
            DenominationTier::Max => 10_000_000_000_000, // 10,000 SOL
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DenominationTier::Micro),
            1 => Some(DenominationTier::Mini),
            2 => Some(DenominationTier::Small),
            3 => Some(DenominationTier::Medium),
            4 => Some(DenominationTier::Large),
            5 => Some(DenominationTier::XLarge),
            6 => Some(DenominationTier::XXLarge),
            7 => Some(DenominationTier::Max),
            _ => None,
        }
    }
}

/// Privacy Pool Configuration
/// One pool per (input_mint, output_mint, denomination_tier) tuple
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PrivacyPoolConfig {
    /// Discriminator for account type
    pub discriminator: [u8; 8],
    /// Input token mint
    pub input_mint: Address,
    /// Output token mint
    pub output_mint: Address,
    /// Denomination tier (determines fixed deposit amount)
    pub denomination_tier: u8,
    /// Exact amount for this tier (in input token's smallest unit)
    pub denomination_amount: u64,
    /// Vault PDA (owns all intermediate accounts)
    pub vault_pda: Address,
    /// Vault PDA bump seed
    pub vault_pda_bump: u8,
    /// Vault's SPL token account for input token
    pub vault_input_ata: Address,
    /// Vault's SPL token account for output token
    pub vault_output_ata: Address,
    /// DEX pool address (Meteora, Orca, etc.)
    pub dex_pool: Address,
    /// DEX type (0=Meteora DAMM, 1=DLMM, etc.)
    pub dex_type: u8,
    /// Total deposits ever made to this pool
    pub total_deposits: u64,
    /// Total claims ever made from this pool
    pub total_claims: u64,
    /// Current pending claims (deposits - claims)
    pub pending_claims: u64,
    /// Total input volume (for stats)
    pub total_volume_input: u64,
    /// Total output volume (for stats)
    pub total_volume_output: u64,
    /// Is pool active? (admin can pause)
    pub is_active: u8,
    /// Pool authority (can update settings)
    pub authority: Address,
    /// Reserved for future use
    pub _reserved: [u8; 64],
}

impl PrivacyPoolConfig {
    pub const LEN: usize = 8 + 32 + 32 + 1 + 8 + 32 + 1 + 32 + 32 + 32 + 1 + 8 + 8 + 8 + 8 + 8 + 1 + 32 + 64;
    pub const DISCRIMINATOR: [u8; 8] = [0x70, 0x72, 0x69, 0x76, 0x70, 0x6f, 0x6f, 0x6c]; // "privpool"
    pub const SEED: &'static [u8] = b"privacy_pool";
}

/// Commitment Account (V6 - User Slippage Protection)
/// Stores a single deposit commitment with status tracking
/// Flow: Pending -> Swapped -> PartialClaim (optional) -> FullyClaimed
/// Supports partial withdrawals for enhanced privacy
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CommitmentAccount {
    /// Discriminator for account type
    pub discriminator: [u8; 8],
    /// The commitment hash = hash(secret || nonce)
    pub commitment_hash: [u8; 32],
    /// Which pool this commitment belongs to
    pub pool: Address,
    /// Input token mint (what user deposited)
    pub input_mint: Address,
    /// Input amount deposited (before swap)
    pub input_amount: u64,
    /// Output amount user will receive (set after swap by keeper)
    pub output_amount: u64,
    /// Slot when deposit was made
    pub deposit_slot: u64,
    /// Unix timestamp when deposit was made
    pub deposit_timestamp: i64,
    /// Current status: 0=Pending, 1=Swapped, 2=PartialClaim, 3=FullyClaimed
    pub status: u8,
    /// Slot when swapped by keeper (0 if not swapped)
    pub swap_slot: u64,
    /// Slot when claimed (0 if not claimed)
    pub claim_slot: u64,
    /// DEX type used for swap (set by keeper)
    pub dex_type: u8,
    /// Amount already claimed (for partial withdrawals)
    /// remaining = output_amount - claimed_amount
    pub claimed_amount: u64,
    /// HIGH-003 FIX: User's minimum output amount (slippage protection)
    /// Keeper's min_output_amount MUST be >= this value
    /// Prevents keeper from setting low slippage to extract value
    pub user_min_output: u64,
    /// CRIT-007 FIX: Claim authority pubkey (anti-frontrunning)
    /// Only this pubkey can sign claim transactions
    /// User generates fresh keypair, shares private key with recipient off-chain
    pub claim_authority: Address,
}

impl CommitmentAccount {
    // 8 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 8 + 8 + 1 + 8 + 8 + 32 = 202 bytes
    // V5: 194, V6: 202 (added 8 for user_min_output)
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 8 + 8 + 1 + 8 + 8 + 32;
    pub const DISCRIMINATOR: [u8; 8] = [0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x76, 0x36]; // "commitv6"
    pub const SEED: &'static [u8] = b"commitment";

    /// Check if commitment is pending (waiting for keeper to swap)
    pub fn is_pending(&self) -> bool {
        self.status == CommitmentStatus::Pending as u8
    }

    /// Check if commitment is swapped (ready for first claim)
    pub fn is_swapped(&self) -> bool {
        self.status == CommitmentStatus::Swapped as u8
    }

    /// Check if commitment is partially claimed (more claims possible)
    pub fn is_partial(&self) -> bool {
        self.status == CommitmentStatus::PartialClaim as u8
    }

    /// Check if commitment is fully claimed (nullified)
    pub fn is_fully_claimed(&self) -> bool {
        self.status == CommitmentStatus::FullyClaimed as u8
    }

    /// Check if commitment can be claimed (Swapped or PartialClaim)
    pub fn is_claimable(&self) -> bool {
        self.is_swapped() || self.is_partial()
    }

    /// Get remaining claimable amount
    pub fn remaining_amount(&self) -> u64 {
        self.output_amount.saturating_sub(self.claimed_amount)
    }
}

/// Nullifier Registry
/// Tracks claimed commitments to prevent double-spend
/// Uses a simple list for now, can upgrade to bloom filter later
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NullifierRegistry {
    /// Discriminator for account type
    pub discriminator: [u8; 8],
    /// Which pool this registry belongs to
    pub pool: Address,
    /// Number of nullifiers stored
    pub count: u32,
    /// Max capacity before needing expansion
    pub capacity: u32,
    // Nullifier hashes follow in remaining account data
    // Each nullifier is 32 bytes
}

impl NullifierRegistry {
    pub const HEADER_LEN: usize = 8 + 32 + 4 + 4;
    pub const DISCRIMINATOR: [u8; 8] = [0x6e, 0x75, 0x6c, 0x6c, 0x69, 0x66, 0x79, 0x72]; // "nullifyr"
    pub const SEED: &'static [u8] = b"nullifier";
    pub const NULLIFIER_SIZE: usize = 32;
}

// ============================================================
// V2 SEEDS
// ============================================================

pub mod seeds_v2 {
    pub const PRIVACY_POOL: &[u8] = b"privacy_pool";
    pub const VAULT: &[u8] = b"vault";
    pub const COMMITMENT: &[u8] = b"commitment";
    pub const NULLIFIER: &[u8] = b"nullifier";
}

// ============================================================
// UNIVERSAL POOL CONSTANTS
// ============================================================

/// Universal mint address used for pool/vault PDA derivation
/// This allows a single pool to accept ANY token
/// The actual token is tracked in each commitment's input_mint field
/// Using program ID as the universal mint for uniqueness
pub const UNIVERSAL_MINT: [u8; 32] = [
    0x55, 0x4e, 0x49, 0x56, 0x45, 0x52, 0x53, 0x41, // "UNIVERSA"
    0x4c, 0x5f, 0x50, 0x52, 0x49, 0x56, 0x41, 0x43, // "L_PRIVAC"
    0x59, 0x5f, 0x50, 0x4f, 0x4f, 0x4c, 0x5f, 0x56, // "Y_POOL_V"
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // "1" + padding
];

// ============================================================
// V1 STATE (Legacy - keeping for compatibility)
// ============================================================

/// Program configuration account
/// Stores the owner's encryption public key for audit log decryption
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PrivacySwapConfig {
    /// Discriminator for account type
    pub discriminator: [u8; 8],
    /// Program authority (can update config)
    pub authority: Address,
    /// Owner's X25519 public key for encrypting audit logs
    pub owner_encryption_pubkey: [u8; 32],
    /// Total swaps processed (for stats)
    pub total_swaps: u64,
    /// Bump seed for PDA derivation
    pub bump: u8,
    /// Reserved for future use
    pub _reserved: [u8; 64],
}

impl PrivacySwapConfig {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 1 + 64; // 145 bytes
    pub const DISCRIMINATOR: [u8; 8] = [0x70, 0x72, 0x69, 0x76, 0x63, 0x66, 0x67, 0x00]; // "privcfg\0"
    pub const SEED: &'static [u8] = b"privacy_swap_config";
}

/// Audit log entry stored on-chain
/// Contains encrypted swap details that only the owner can decrypt
#[repr(C)]
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    /// Discriminator for account type
    pub discriminator: [u8; 8],
    /// Slot when swap occurred
    pub slot: u64,
    /// Unix timestamp of swap
    pub timestamp: i64,
    /// Encrypted audit data
    /// Contains: user_wallet, input_mint, output_mint, amounts, etc.
    /// Encrypted with owner's X25519 public key
    pub encrypted_data: [u8; 256], // Fixed size for simplicity
    /// Length of actual encrypted data within the buffer
    pub encrypted_data_len: u16,
}

impl AuditLogEntry {
    pub const LEN: usize = 8 + 8 + 8 + 256 + 2; // 282 bytes
    pub const DISCRIMINATOR: [u8; 8] = [0x61, 0x75, 0x64, 0x69, 0x74, 0x6c, 0x6f, 0x67]; // "auditlog"
}

/// Temporary account for holding decompressed tokens during swap
/// This is a PDA that owns the temporary SPL token accounts
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SwapEscrow {
    /// Discriminator for account type
    pub discriminator: [u8; 8],
    /// User who initiated the swap
    pub user: Address,
    /// Input token mint
    pub input_mint: Address,
    /// Output token mint
    pub output_mint: Address,
    /// Expected input amount
    pub input_amount: u64,
    /// Minimum output amount
    pub min_output_amount: u64,
    /// Slot when escrow was created (for timeout)
    pub created_slot: u64,
    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl SwapEscrow {
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 8 + 8 + 1; // 129 bytes
    pub const DISCRIMINATOR: [u8; 8] = [0x73, 0x77, 0x61, 0x70, 0x65, 0x73, 0x63, 0x72]; // "swapescr"
    pub const SEED: &'static [u8] = b"swap_escrow";
}

/// PDA seeds for deriving program addresses
pub mod seeds {
    pub const CONFIG: &[u8] = b"privacy_swap_config";
    pub const ESCROW: &[u8] = b"swap_escrow";
    pub const AUDIT_LOG: &[u8] = b"audit_log";
    pub const TOKEN_AUTHORITY: &[u8] = b"token_authority";
}
