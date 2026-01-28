//! Program errors

use pinocchio::error::ProgramError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PrivacySwapError {
    /// Invalid instruction discriminator
    InvalidInstruction = 0,
    /// Invalid account provided
    InvalidAccount = 1,
    /// Slippage tolerance exceeded
    SlippageExceeded = 2,
    /// Invalid proof provided
    InvalidProof = 3,
    /// Insufficient input amount
    InsufficientInput = 4,
    /// Invalid DEX type
    InvalidDexType = 5,
    /// CPI call failed
    CpiFailed = 6,
    /// Invalid encrypted audit data
    InvalidAuditData = 7,
    /// Account not writable
    AccountNotWritable = 8,
    /// Missing required signer
    MissingRequiredSigner = 9,
    /// Invalid owner
    InvalidOwner = 10,
    /// Invalid commitment (secret/nonce doesn't match)
    InvalidCommitment = 11,
    /// Commitment already claimed
    AlreadyClaimed = 12,
    /// Failed to borrow account data
    AccountBorrowFailed = 13,
    /// NFT not found or invalid
    InvalidNft = 14,
    /// NFT already redeemed
    NftAlreadyRedeemed = 15,
    /// Invalid PDA derivation
    InvalidPda = 16,
    /// Invalid NFT ownership (holder doesn't own NFT)
    InvalidNftOwnership = 17,
    /// Invalid mint authority
    InvalidMintAuthority = 18,
    /// Nullifier registry is full
    NullifierRegistryFull = 19,
    /// Pool is not active (paused)
    PoolNotActive = 20,
    /// Invalid pool configuration
    InvalidPoolConfig = 21,
    /// Invalid program ID passed for CPI (CVE-001 fix)
    /// Attacker attempted to pass a fake program
    InvalidProgram = 22,
    /// Commitment not in Swapped status (keeper hasn't executed swap)
    /// User tried to claim before keeper executed the swap
    CommitmentNotSwapped = 23,
    /// Math overflow during fee calculation
    MathOverflow = 24,
    /// Invalid claim percentage (must be 25, 50, 75, or 100)
    /// Using fixed tiers for larger anonymity sets
    InvalidClaimPercentage = 25,
    /// Insufficient remaining amount for requested claim
    /// Remaining balance is less than what user wants to claim
    InsufficientRemainingAmount = 26,
    /// Unauthorized keeper (CRIT-003 fix)
    /// Only pool authority can execute swaps
    UnauthorizedKeeper = 27,
    /// Invalid token mint for destination ATA (CRIT-004 fix)
    /// Destination ATA mint must match output token
    InvalidDestinationMint = 28,
    /// Token account is frozen (SEC-006 fix)
    AccountFrozen = 29,
    /// Invalid commitment status value (SEC-008 fix)
    InvalidCommitmentStatus = 30,
    /// Pool config doesn't match commitment's pool (SEC-011 fix)
    PoolMismatch = 31,
    /// Vault ATA not owned by vault PDA (SEC-012 fix)
    InvalidVaultAta = 32,
    /// Account already initialized (SEC-014 fix)
    AccountAlreadyInitialized = 33,
    /// Swap execution failed (SEC-005 fix)
    SwapFailed = 34,
    /// Insufficient output from swap (SEC-005 fix)
    InsufficientOutput = 35,
    /// Refund timeout not reached (HIGH-002 fix)
    /// Commitment must be Pending for at least REFUND_TIMEOUT_SLOTS
    RefundTooEarly = 36,
    /// Commitment not in Pending status (cannot refund)
    NotPending = 37,
    /// Unauthorized claim authority (CRIT-007 fix)
    /// Only the stored claim_authority pubkey can claim
    UnauthorizedClaimAuthority = 38,
    /// Duplicate account detected (MED-001 fix)
    /// Same account passed for multiple parameters that must be distinct
    DuplicateAccount = 39,
}

impl From<PrivacySwapError> for ProgramError {
    fn from(e: PrivacySwapError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
