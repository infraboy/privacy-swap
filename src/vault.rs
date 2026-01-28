//! Vault PDA helpers and CPI wrappers for V2 privacy pools
//!
//! The vault PDA owns all intermediate accounts, breaking the link
//! between depositor and claimant.
//!
//! PRIVACY NOTE: Verbose logging is disabled by default.

use pinocchio::{
    AccountView,
    Address,
    ProgramResult,
    error::ProgramError,
};
use solana_instruction_view::{
    cpi::{invoke, invoke_signed, Seed, Signer},
    seeds, InstructionAccount, InstructionView,
};

// Conditional logging - only enabled with verbose-logs feature
#[cfg(feature = "verbose-logs")]
use solana_program_log::log;

#[cfg(feature = "verbose-logs")]
macro_rules! verbose_log {
    ($($arg:tt)*) => { log!($($arg)*) };
}

#[cfg(not(feature = "verbose-logs"))]
macro_rules! verbose_log {
    ($($arg:tt)*) => { };
}

use crate::state::seeds_v2;

// ============================================================
// COMMITMENT HASHING (SHA256)
// ============================================================

/// Compute commitment hash from secret and nonce
/// commitment = sha256(secret || nonce_le_bytes)
///
/// We use the sol_sha256 syscall which is available on Solana
pub fn compute_commitment(secret: &[u8; 32], nonce: u64) -> [u8; 32] {
    // Build input: secret (32 bytes) || nonce (8 bytes little-endian)
    let mut input = [0u8; 40];
    input[0..32].copy_from_slice(secret);
    input[32..40].copy_from_slice(&nonce.to_le_bytes());

    // Use Solana's SHA256 syscall
    let mut result = [0u8; 32];

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        // sol_sha256 expects an array of slices (for hashing multiple buffers)
        // We pass a single slice containing our input data
        let vals: &[&[u8]] = &[&input[..]];
        unsafe {
            pinocchio::syscalls::sol_sha256(
                vals.as_ptr() as *const u8,
                vals.len() as u64,  // Number of slices (1)
                result.as_mut_ptr(),
            );
        }
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        // For testing off-chain, use a simple XOR hash
        // In production this branch is never taken
        for (i, byte) in input.iter().enumerate() {
            result[i % 32] ^= byte;
        }
    }

    result
}

/// Verify that a secret + nonce produces the expected commitment
pub fn verify_commitment(
    secret: &[u8; 32],
    nonce: u64,
    expected_commitment: &[u8; 32],
) -> bool {
    let computed = compute_commitment(secret, nonce);
    computed == *expected_commitment
}

// ============================================================
// VAULT CPI HELPERS (with invoke_signed)
// ============================================================

/// Transfer SPL tokens FROM vault using invoke_signed
///
/// The vault PDA signs the transfer, allowing the program to move tokens
/// from vault-owned accounts without user signature.
///
/// Takes the individual seed components for the vault PDA
pub fn vault_transfer_spl<'a>(
    source: &'a AccountView,
    destination: &'a AccountView,
    vault_authority: &'a AccountView,
    token_program: &'a AccountView,
    amount: u64,
    input_mint: &[u8],
    output_mint: &[u8],
    tier: &[u8],
    bump: &[u8],
) -> ProgramResult {
    verbose_log!("Vault transferring SPL tokens...");

    // SPL Token transfer instruction data
    // Instruction 3 = Transfer, followed by amount (8 bytes LE)
    let mut ix_data = [0u8; 9];
    ix_data[0] = 3; // Transfer instruction
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        InstructionAccount::writable(source.address()),
        InstructionAccount::writable(destination.address()),
        InstructionAccount::readonly_signer(vault_authority.address()),
    ];

    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &ix_data,
    };

    // Create seeds array using the seeds! macro
    let vault_seeds = seeds!(
        seeds_v2::VAULT,
        input_mint,
        output_mint,
        tier,
        bump
    );
    let signer = Signer::from(&vault_seeds);

    let account_infos = [
        source,
        destination,
        vault_authority,
        token_program,
    ];

    invoke_signed(&instruction, &account_infos, &[signer])
}

// ============================================================
// METEORA SWAP WITH VAULT SIGNING
// ============================================================

/// Meteora DAMM v2 Program ID (cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG)
const METEORA_DAMM_V2: Address = Address::new_from_array([
    0x09, 0x2d, 0x21, 0x35, 0x65, 0x7a, 0x15, 0x9c,
    0x2b, 0x87, 0xd4, 0xb6, 0x6a, 0x70, 0xdb, 0x8e,
    0x97, 0x52, 0x38, 0x9f, 0xf7, 0x6a, 0xaf, 0x20,
    0x6c, 0xed, 0x06, 0x3a, 0x38, 0xf9, 0x5a, 0xed,
]);

/// Meteora swap discriminator
const METEORA_SWAP_DISC: [u8; 8] = [0xf8, 0xc6, 0x9e, 0x91, 0xe1, 0x75, 0x87, 0xc8];

/// Execute Meteora swap with vault PDA as authority
///
/// The vault owns the input/output ATAs, so the swap happens
/// without any user accounts being visible.
pub fn vault_meteora_swap<'a>(
    pool: &'a AccountView,
    pool_authority: &'a AccountView,
    vault_input_ata: &'a AccountView,
    vault_output_ata: &'a AccountView,
    pool_vault_a: &'a AccountView,
    pool_vault_b: &'a AccountView,
    vault_pda: &'a AccountView,
    token_program: &'a AccountView,
    input_mint_account: &'a AccountView,
    output_mint_account: &'a AccountView,
    amount_in: u64,
    min_amount_out: u64,
    input_mint: &[u8],
    output_mint: &[u8],
    tier: &[u8],
    bump: &[u8],
) -> ProgramResult {
    verbose_log!("Vault swapping on Meteora...");

    // Build swap instruction data
    let mut ix_data = [0u8; 24];
    ix_data[0..8].copy_from_slice(&METEORA_SWAP_DISC);
    ix_data[8..16].copy_from_slice(&amount_in.to_le_bytes());
    ix_data[16..24].copy_from_slice(&min_amount_out.to_le_bytes());

    // Meteora swap accounts
    // Note: vault_input_ata and vault_output_ata are VAULT-OWNED, not user's!
    let accounts = [
        InstructionAccount::writable(pool.address()),
        InstructionAccount::readonly(pool_authority.address()),
        InstructionAccount::writable(vault_input_ata.address()),  // Vault's ATA!
        InstructionAccount::writable(vault_output_ata.address()), // Vault's ATA!
        InstructionAccount::writable(pool_vault_a.address()),
        InstructionAccount::writable(pool_vault_b.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(input_mint_account.address()),
        InstructionAccount::readonly(output_mint_account.address()),
        // Vault PDA as the authority for the ATAs
        InstructionAccount::readonly_signer(vault_pda.address()),
    ];

    let instruction = InstructionView {
        program_id: &METEORA_DAMM_V2,
        accounts: &accounts,
        data: &ix_data,
    };

    // Create seeds array using the seeds! macro
    let vault_seeds = seeds!(
        seeds_v2::VAULT,
        input_mint,
        output_mint,
        tier,
        bump
    );
    let signer = Signer::from(&vault_seeds);

    let account_infos = [
        pool,
        pool_authority,
        vault_input_ata,
        vault_output_ata,
        pool_vault_a,
        pool_vault_b,
        token_program,
        token_program,
        input_mint_account,
        output_mint_account,
        vault_pda,
    ];

    invoke_signed(&instruction, &account_infos, &[signer])
}

// ============================================================
// COMMITMENT ACCOUNT HELPERS
// ============================================================

/// Commitment account data layout (V5 - Anti-Frontrunning)
/// Must match CommitmentAccount in state.rs
///
/// Status values:
/// - 0 = Pending (waiting for keeper swap)
/// - 1 = Swapped (ready for claim)
/// - 2 = PartialClaim (some claimed, more available)
/// - 3 = FullyClaimed (nullified)
pub mod commitment_layout {
    pub const DISCRIMINATOR_OFFSET: usize = 0;
    pub const COMMITMENT_HASH_OFFSET: usize = 8;
    pub const POOL_OFFSET: usize = 40;
    pub const INPUT_MINT_OFFSET: usize = 72;
    pub const INPUT_AMOUNT_OFFSET: usize = 104;
    pub const OUTPUT_AMOUNT_OFFSET: usize = 112;
    pub const DEPOSIT_SLOT_OFFSET: usize = 120;
    pub const DEPOSIT_TIMESTAMP_OFFSET: usize = 128;
    pub const STATUS_OFFSET: usize = 136;  // 0=Pending, 1=Swapped, 2=PartialClaim, 3=FullyClaimed
    pub const SWAP_SLOT_OFFSET: usize = 137;
    pub const CLAIM_SLOT_OFFSET: usize = 145;
    pub const DEX_TYPE_OFFSET: usize = 153;
    pub const CLAIMED_AMOUNT_OFFSET: usize = 154;  // V4: tracks partial claims
    // HIGH-003 FIX: User's minimum output (slippage protection)
    // Keeper's min_output_amount MUST be >= this value
    pub const USER_MIN_OUTPUT_OFFSET: usize = 162;  // V6: 8 bytes
    // CRIT-007 FIX: Claim authority pubkey (anti-frontrunning)
    // Only this pubkey can sign claim transactions
    pub const CLAIM_AUTHORITY_OFFSET: usize = 170;  // V6: 32 bytes (shifted from 162)
    // Legacy alias for backwards compatibility
    pub const IS_CLAIMED_OFFSET: usize = STATUS_OFFSET;
}

/// Read output amount from commitment account
pub fn read_commitment_output_amount(data: &[u8]) -> Option<u64> {
    if data.len() < commitment_layout::OUTPUT_AMOUNT_OFFSET + 8 {
        return None;
    }
    let bytes: [u8; 8] = data[commitment_layout::OUTPUT_AMOUNT_OFFSET..commitment_layout::OUTPUT_AMOUNT_OFFSET + 8]
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Read commitment hash from commitment account
pub fn read_commitment_hash(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < commitment_layout::COMMITMENT_HASH_OFFSET + 32 {
        return None;
    }
    let hash: [u8; 32] = data[commitment_layout::COMMITMENT_HASH_OFFSET..commitment_layout::COMMITMENT_HASH_OFFSET + 32]
        .try_into()
        .ok()?;
    Some(hash)
}

/// Read commitment status (V3: 0=Pending, 1=Swapped, 2=Claimed)
pub fn read_commitment_status(data: &[u8]) -> Option<u8> {
    if data.len() <= commitment_layout::STATUS_OFFSET {
        return None;
    }
    Some(data[commitment_layout::STATUS_OFFSET])
}

/// Check if commitment is in Swapped status (ready for first claim)
pub fn is_commitment_swapped(data: &[u8]) -> bool {
    if data.len() <= commitment_layout::STATUS_OFFSET {
        return false;
    }
    // Status 1 = Swapped
    data[commitment_layout::STATUS_OFFSET] == 1
}

/// Check if commitment is in PartialClaim status (more claims available)
pub fn is_commitment_partial(data: &[u8]) -> bool {
    if data.len() <= commitment_layout::STATUS_OFFSET {
        return false;
    }
    // Status 2 = PartialClaim
    data[commitment_layout::STATUS_OFFSET] == 2
}

/// Check if commitment is fully claimed (nullified)
pub fn is_commitment_fully_claimed(data: &[u8]) -> bool {
    if data.len() <= commitment_layout::STATUS_OFFSET {
        return false;
    }
    // Status 3 = FullyClaimed
    data[commitment_layout::STATUS_OFFSET] == 3
}

/// Check if commitment is already claimed (legacy - now checks FullyClaimed)
pub fn is_commitment_claimed(data: &[u8]) -> bool {
    is_commitment_fully_claimed(data)
}

/// Check if commitment is claimable (Swapped or PartialClaim)
pub fn is_commitment_claimable(data: &[u8]) -> bool {
    is_commitment_swapped(data) || is_commitment_partial(data)
}

/// Read claimed_amount from commitment account (V4 fractional claims)
pub fn read_commitment_claimed_amount(data: &[u8]) -> Option<u64> {
    if data.len() < commitment_layout::CLAIMED_AMOUNT_OFFSET + 8 {
        return None;
    }
    let bytes: [u8; 8] = data[commitment_layout::CLAIMED_AMOUNT_OFFSET..commitment_layout::CLAIMED_AMOUNT_OFFSET + 8]
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Read user_min_output from commitment account (V6 slippage protection)
/// Returns the user's minimum acceptable output amount
pub fn read_commitment_user_min_output(data: &[u8]) -> Option<u64> {
    if data.len() < commitment_layout::USER_MIN_OUTPUT_OFFSET + 8 {
        return None;
    }
    let bytes: [u8; 8] = data[commitment_layout::USER_MIN_OUTPUT_OFFSET..commitment_layout::USER_MIN_OUTPUT_OFFSET + 8]
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Read claim_authority from commitment account (V5 anti-frontrunning)
/// Returns the pubkey that must sign claim transactions
pub fn read_commitment_claim_authority(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < commitment_layout::CLAIM_AUTHORITY_OFFSET + 32 {
        return None;
    }
    let authority: [u8; 32] = data[commitment_layout::CLAIM_AUTHORITY_OFFSET..commitment_layout::CLAIM_AUTHORITY_OFFSET + 32]
        .try_into()
        .ok()?;
    Some(authority)
}

/// Calculate remaining amount (output_amount - claimed_amount)
pub fn get_remaining_amount(data: &[u8]) -> Option<u64> {
    let output = read_commitment_output_amount(data)?;
    let claimed = read_commitment_claimed_amount(data).unwrap_or(0);
    Some(output.saturating_sub(claimed))
}

/// Mark commitment as fully claimed (sets status to 3 and records claim_slot)
pub fn mark_commitment_claimed(data: &mut [u8], claim_slot: u64) {
    if data.len() > commitment_layout::STATUS_OFFSET {
        data[commitment_layout::STATUS_OFFSET] = 3; // FullyClaimed status
    }
    if data.len() >= commitment_layout::CLAIM_SLOT_OFFSET + 8 {
        data[commitment_layout::CLAIM_SLOT_OFFSET..commitment_layout::CLAIM_SLOT_OFFSET + 8]
            .copy_from_slice(&claim_slot.to_le_bytes());
    }
}

/// Update commitment for partial claim (V4 fractional withdrawals)
///
/// - Adds claim_amount to claimed_amount
/// - Sets status to PartialClaim (2) or FullyClaimed (3) based on remaining
/// - Updates claim_slot
///
/// Returns the new remaining amount after this claim
pub fn update_commitment_partial_claim(
    data: &mut [u8],
    claim_amount: u64,
    claim_slot: u64,
) -> Option<u64> {
    // Read current values
    let output_amount = read_commitment_output_amount(data)?;
    let current_claimed = read_commitment_claimed_amount(data).unwrap_or(0);

    // Calculate new claimed amount
    // MED-001 FIX: Cap new_claimed at output_amount to prevent any overflow scenarios
    let new_claimed = current_claimed.saturating_add(claim_amount);
    let new_claimed = new_claimed.min(output_amount);
    let remaining = output_amount.saturating_sub(new_claimed);

    // Update claimed_amount
    if data.len() >= commitment_layout::CLAIMED_AMOUNT_OFFSET + 8 {
        data[commitment_layout::CLAIMED_AMOUNT_OFFSET..commitment_layout::CLAIMED_AMOUNT_OFFSET + 8]
            .copy_from_slice(&new_claimed.to_le_bytes());
    }

    // Update status based on remaining
    if remaining == 0 {
        // Fully claimed
        if data.len() > commitment_layout::STATUS_OFFSET {
            data[commitment_layout::STATUS_OFFSET] = 3; // FullyClaimed
        }
    } else {
        // Partial claim
        if data.len() > commitment_layout::STATUS_OFFSET {
            data[commitment_layout::STATUS_OFFSET] = 2; // PartialClaim
        }
    }

    // Update claim_slot
    if data.len() >= commitment_layout::CLAIM_SLOT_OFFSET + 8 {
        data[commitment_layout::CLAIM_SLOT_OFFSET..commitment_layout::CLAIM_SLOT_OFFSET + 8]
            .copy_from_slice(&claim_slot.to_le_bytes());
    }

    Some(remaining)
}

// ============================================================
// ACCOUNT CREATION HELPERS (System Program CPI)
// ============================================================

/// System Program ID (reserved for future use)
#[allow(dead_code)]
const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);

/// SPL Token Program ID (reserved for future use)
#[allow(dead_code)]
const TOKEN_PROGRAM: Address = Address::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
]);

/// Associated Token Account Program ID
const ATA_PROGRAM: Address = Address::new_from_array([
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1,
    0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84,
    0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
]);

/// Create a new account via System Program CPI
/// Used for creating pool config, commitment accounts, etc.
///
/// NOTE: For PDA accounts, use `create_account_with_seeds` instead.
pub fn create_account<'a>(
    payer: &'a AccountView,
    new_account: &'a AccountView,
    system_program: &'a AccountView,
    lamports: u64,
    space: u64,
    owner: &Address,
    signer_seeds: Option<&[&[u8]]>,
) -> ProgramResult {
    verbose_log!("Creating account with {} lamports, {} bytes", lamports, space);

    // System Program CreateAccount instruction data:
    // [0..4]: discriminator = 0
    // [4..12]: lamports (u64 LE)
    // [12..20]: space (u64 LE)
    // [20..52]: owner (32 bytes)
    let mut ix_data = [0u8; 52];
    ix_data[0..4].copy_from_slice(&0u32.to_le_bytes()); // CreateAccount discriminator
    ix_data[4..12].copy_from_slice(&lamports.to_le_bytes());
    ix_data[12..20].copy_from_slice(&space.to_le_bytes());
    ix_data[20..52].copy_from_slice(owner.as_ref());

    let accounts = [
        InstructionAccount::writable_signer(payer.address()),
        InstructionAccount::writable_signer(new_account.address()),
    ];

    let instruction = InstructionView {
        program_id: system_program.address(),
        accounts: &accounts,
        data: &ix_data,
    };

    let account_infos = [payer, new_account, system_program];

    if let Some(seeds_slice) = signer_seeds {
        // Convert &[&[u8]] to Vec<Seed> for invoke_signed
        let seeds_vec: alloc::vec::Vec<Seed> = seeds_slice.iter()
            .map(|s| Seed::from(*s))
            .collect();
        let signer = Signer::from(seeds_vec.as_slice());
        invoke_signed(&instruction, &account_infos, &[signer])
    } else {
        // Regular account creation
        invoke(&instruction, &account_infos)
    }
}

/// Create Associated Token Account via ATA Program CPI
/// Uses CreateIdempotent (discriminator = 1) to avoid errors if exists
pub fn create_ata<'a>(
    payer: &'a AccountView,
    ata: &'a AccountView,
    wallet: &'a AccountView,
    mint: &'a AccountView,
    system_program: &'a AccountView,
    token_program: &'a AccountView,
) -> ProgramResult {
    verbose_log!("Creating ATA...");

    // ATA CreateIdempotent instruction data: single byte = 1
    let ix_data = [1u8];

    let accounts = [
        InstructionAccount::writable_signer(payer.address()),
        InstructionAccount::writable(ata.address()),
        InstructionAccount::readonly(wallet.address()),
        InstructionAccount::readonly(mint.address()),
        InstructionAccount::readonly(system_program.address()),
        InstructionAccount::readonly(token_program.address()),
    ];

    let instruction = InstructionView {
        program_id: &ATA_PROGRAM,
        accounts: &accounts,
        data: &ix_data,
    };

    let account_infos = [
        payer,
        ata,
        wallet,
        mint,
        system_program,
        token_program,
    ];

    invoke(&instruction, &account_infos)
}

/// Calculate minimum lamports for rent exemption
/// Calculate rent-exempt balance for an account
/// Formula: (128 + space) * lamports_per_byte_year * exemption_threshold
/// Where lamports_per_byte_year ≈ 3480 and exemption_threshold = 2
pub fn calculate_rent_exempt_balance(space: u64) -> u64 {
    // Solana rent: (128 + space) * 3480 * 2
    // = (128 + space) * 6960
    (128 + space) * 6960
}

// ============================================================
// NULLIFIER HELPERS
// ============================================================

/// Check if a commitment has been nullified (already claimed)
pub fn is_nullified(
    nullifier_data: &[u8],
    commitment_hash: &[u8; 32],
) -> bool {
    // Nullifier registry format:
    // [0..8]: discriminator
    // [8..40]: pool pubkey
    // [40..44]: count (u32)
    // [44..48]: capacity (u32)
    // [48..]: nullifier hashes (32 bytes each)

    if nullifier_data.len() < 48 {
        return false;
    }

    let count = u32::from_le_bytes(
        nullifier_data[40..44].try_into().unwrap_or([0; 4])
    ) as usize;

    let nullifiers_start = 48;

    for i in 0..count {
        let start = nullifiers_start + (i * 32);
        let end = start + 32;

        if end > nullifier_data.len() {
            break;
        }

        if &nullifier_data[start..end] == commitment_hash {
            return true; // Already claimed!
        }
    }

    false
}

/// Add a nullifier to the registry
/// Returns error if registry is full
pub fn add_nullifier(
    nullifier_data: &mut [u8],
    commitment_hash: &[u8; 32],
) -> Result<(), ProgramError> {
    if nullifier_data.len() < 48 {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let count = u32::from_le_bytes(
        nullifier_data[40..44].try_into().unwrap_or([0; 4])
    ) as usize;

    let capacity = u32::from_le_bytes(
        nullifier_data[44..48].try_into().unwrap_or([0; 4])
    ) as usize;

    if count >= capacity {
        verbose_log!("Nullifier registry full!");
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Add the new nullifier
    let nullifiers_start = 48;
    let new_pos = nullifiers_start + (count * 32);

    if new_pos + 32 > nullifier_data.len() {
        return Err(ProgramError::AccountDataTooSmall);
    }

    nullifier_data[new_pos..new_pos + 32].copy_from_slice(commitment_hash);

    // Increment count
    let new_count = (count + 1) as u32;
    nullifier_data[40..44].copy_from_slice(&new_count.to_le_bytes());

    Ok(())
}

/// Check if nullifier registry needs expansion
pub fn nullifier_needs_expansion(nullifier_data: &[u8]) -> bool {
    if nullifier_data.len() < 48 {
        return true;
    }

    let count = u32::from_le_bytes(
        nullifier_data[40..44].try_into().unwrap_or([0; 4])
    ) as usize;

    let capacity = u32::from_le_bytes(
        nullifier_data[44..48].try_into().unwrap_or([0; 4])
    ) as usize;

    // Return true if we're at 90% capacity
    count >= (capacity * 9) / 10
}

/// Initialize a new nullifier registry
pub fn init_nullifier_registry(
    data: &mut [u8],
    pool: &[u8; 32],
    capacity: u32,
) {
    use crate::state::NullifierRegistry;

    if data.len() < NullifierRegistry::HEADER_LEN {
        return;
    }

    // Write discriminator
    data[0..8].copy_from_slice(&NullifierRegistry::DISCRIMINATOR);
    // Write pool
    data[8..40].copy_from_slice(pool);
    // Write count = 0
    data[40..44].copy_from_slice(&0u32.to_le_bytes());
    // Write capacity
    data[44..48].copy_from_slice(&capacity.to_le_bytes());
}

/// Get the required account size for a nullifier registry with given capacity
pub fn nullifier_registry_size(capacity: u32) -> usize {
    use crate::state::NullifierRegistry;
    NullifierRegistry::HEADER_LEN + (capacity as usize * 32)
}

// ============================================================
// POOL CONFIG HELPERS
// ============================================================

/// Initialize pool config account data
pub fn init_pool_config(
    data: &mut [u8],
    input_mint: &[u8; 32],
    output_mint: &[u8; 32],
    tier: u8,
    denomination_amount: u64,
    vault_pda: &[u8; 32],
    vault_bump: u8,
    vault_input_ata: &[u8; 32],
    vault_output_ata: &[u8; 32],
    dex_pool: &[u8; 32],
    dex_type: u8,
    authority: &[u8; 32],
) {
    use crate::state::PrivacyPoolConfig;

    if data.len() < PrivacyPoolConfig::LEN {
        return;
    }

    let mut offset = 0;

    // Discriminator (8 bytes)
    data[offset..offset + 8].copy_from_slice(&PrivacyPoolConfig::DISCRIMINATOR);
    offset += 8;

    // Input mint (32 bytes)
    data[offset..offset + 32].copy_from_slice(input_mint);
    offset += 32;

    // Output mint (32 bytes)
    data[offset..offset + 32].copy_from_slice(output_mint);
    offset += 32;

    // Tier (1 byte)
    data[offset] = tier;
    offset += 1;

    // Denomination amount (8 bytes)
    data[offset..offset + 8].copy_from_slice(&denomination_amount.to_le_bytes());
    offset += 8;

    // Vault PDA (32 bytes)
    data[offset..offset + 32].copy_from_slice(vault_pda);
    offset += 32;

    // Vault bump (1 byte)
    data[offset] = vault_bump;
    offset += 1;

    // Vault input ATA (32 bytes)
    data[offset..offset + 32].copy_from_slice(vault_input_ata);
    offset += 32;

    // Vault output ATA (32 bytes)
    data[offset..offset + 32].copy_from_slice(vault_output_ata);
    offset += 32;

    // DEX pool (32 bytes)
    data[offset..offset + 32].copy_from_slice(dex_pool);
    offset += 32;

    // DEX type (1 byte)
    data[offset] = dex_type;
    offset += 1;

    // Stats - all zeros initially
    // total_deposits (8 bytes)
    data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
    offset += 8;

    // total_claims (8 bytes)
    data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
    offset += 8;

    // pending_claims (8 bytes)
    data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
    offset += 8;

    // total_volume_input (8 bytes)
    data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
    offset += 8;

    // total_volume_output (8 bytes)
    data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
    offset += 8;

    // is_active = 1 (active)
    data[offset] = 1;
    offset += 1;

    // Authority (32 bytes)
    data[offset..offset + 32].copy_from_slice(authority);
    // Remaining bytes are reserved (already zeroed)
}

/// Update pool stats after a deposit
pub fn update_pool_deposit(data: &mut [u8], input_amount: u64, output_amount: u64) {
    // Offsets in PrivacyPoolConfig:
    // total_deposits at 8+32+32+1+8+32+1+32+32+32+1 = 211
    const TOTAL_DEPOSITS_OFFSET: usize = 211;
    const PENDING_CLAIMS_OFFSET: usize = 227;
    const TOTAL_VOLUME_INPUT_OFFSET: usize = 235;
    const TOTAL_VOLUME_OUTPUT_OFFSET: usize = 243;

    if data.len() < 251 {
        return;
    }

    // Increment total_deposits
    let deposits = u64::from_le_bytes(data[TOTAL_DEPOSITS_OFFSET..TOTAL_DEPOSITS_OFFSET + 8].try_into().unwrap_or([0; 8]));
    data[TOTAL_DEPOSITS_OFFSET..TOTAL_DEPOSITS_OFFSET + 8].copy_from_slice(&(deposits + 1).to_le_bytes());

    // Increment pending_claims
    let pending = u64::from_le_bytes(data[PENDING_CLAIMS_OFFSET..PENDING_CLAIMS_OFFSET + 8].try_into().unwrap_or([0; 8]));
    data[PENDING_CLAIMS_OFFSET..PENDING_CLAIMS_OFFSET + 8].copy_from_slice(&(pending + 1).to_le_bytes());

    // Add to volume
    let vol_in = u64::from_le_bytes(data[TOTAL_VOLUME_INPUT_OFFSET..TOTAL_VOLUME_INPUT_OFFSET + 8].try_into().unwrap_or([0; 8]));
    data[TOTAL_VOLUME_INPUT_OFFSET..TOTAL_VOLUME_INPUT_OFFSET + 8].copy_from_slice(&(vol_in.saturating_add(input_amount)).to_le_bytes());

    let vol_out = u64::from_le_bytes(data[TOTAL_VOLUME_OUTPUT_OFFSET..TOTAL_VOLUME_OUTPUT_OFFSET + 8].try_into().unwrap_or([0; 8]));
    data[TOTAL_VOLUME_OUTPUT_OFFSET..TOTAL_VOLUME_OUTPUT_OFFSET + 8].copy_from_slice(&(vol_out.saturating_add(output_amount)).to_le_bytes());
}

// ============================================================
// COMMITMENT ACCOUNT HELPERS
// ============================================================

/// Initialize a new commitment account
pub fn init_commitment_account(
    data: &mut [u8],
    commitment_hash: &[u8; 32],
    pool: &[u8; 32],
    output_amount: u64,
    deposit_slot: u64,
    deposit_timestamp: i64,
) {
    use crate::state::CommitmentAccount;

    if data.len() < CommitmentAccount::LEN {
        return;
    }

    // Discriminator
    data[0..8].copy_from_slice(&CommitmentAccount::DISCRIMINATOR);
    // Commitment hash
    data[8..40].copy_from_slice(commitment_hash);
    // Pool
    data[40..72].copy_from_slice(pool);
    // Output amount
    data[72..80].copy_from_slice(&output_amount.to_le_bytes());
    // Deposit slot
    data[80..88].copy_from_slice(&deposit_slot.to_le_bytes());
    // Deposit timestamp
    data[88..96].copy_from_slice(&deposit_timestamp.to_le_bytes());
    // is_claimed = 0
    data[96] = 0;
    // claim_slot = 0
    data[97..105].copy_from_slice(&0u64.to_le_bytes());
    // Reserved bytes already zeroed
}

// ============================================================
// LIGHT PROTOCOL CPI HELPERS (for deposit flow)
// ============================================================

/// Light Protocol cToken Program ID (reserved for future use)
#[allow(dead_code)]
const LIGHT_CTOKEN_PROGRAM: Address = Address::new_from_array([
    0x0a, 0x55, 0xd0, 0x10, 0x26, 0xef, 0xc0, 0x2c,
    0xb2, 0x8f, 0x80, 0x82, 0x30, 0x24, 0x05, 0x15,
    0x4c, 0x8b, 0x43, 0x6f, 0x53, 0xb5, 0xce, 0x0b,
    0x46, 0xf5, 0x00, 0xd8, 0x1b, 0x6e, 0x75, 0x83,
]);

/// Transfer compressed tokens (cTokens) via Light Protocol CPI
/// This transfers ownership of compressed tokens without decompressing
pub fn transfer_ctokens<'a>(
    source_owner: &'a AccountView,
    destination_owner: &'a AccountView,
    mint: &'a AccountView,
    ctoken_program: &'a AccountView,
    merkle_tree: &'a AccountView,
    nullifier_queue: &'a AccountView,
    amount: u64,
    proof: &[u8],
    merkle_context: &[u8],
) -> ProgramResult {
    verbose_log!("Transferring {} cTokens...", amount);

    // Light Protocol Transfer instruction
    // The exact format depends on the SDK version
    // This is a simplified version - actual implementation needs full proof data
    let mut ix_data = alloc::vec![0u8; 1 + 8 + proof.len() + merkle_context.len()];
    ix_data[0] = 101; // Transfer2 discriminator
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());
    ix_data[9..9 + proof.len()].copy_from_slice(proof);
    ix_data[9 + proof.len()..].copy_from_slice(merkle_context);

    let accounts = [
        InstructionAccount::readonly_signer(source_owner.address()),
        InstructionAccount::readonly(destination_owner.address()),
        InstructionAccount::readonly(mint.address()),
        InstructionAccount::writable(merkle_tree.address()),
        InstructionAccount::writable(nullifier_queue.address()),
    ];

    let instruction = InstructionView {
        program_id: ctoken_program.address(),
        accounts: &accounts,
        data: &ix_data,
    };

    let account_infos = [
        source_owner,
        destination_owner,
        mint,
        merkle_tree,
        nullifier_queue,
    ];

    invoke(&instruction, &account_infos)
}

/// Read token balance from SPL token account
pub fn read_token_balance(token_account_data: &[u8]) -> u64 {
    // SPL Token account layout: mint(32) + owner(32) + amount(8) + ...
    if token_account_data.len() < 72 {
        return 0;
    }
    u64::from_le_bytes(
        token_account_data[64..72].try_into().unwrap_or([0; 8])
    )
}

/// Transfer SPL tokens from user to vault (user signs)
///
/// This is used during deposit - user transfers their tokens to the vault.
/// Unlike vault_transfer_spl which uses invoke_signed, this uses regular invoke
/// since the user is already a signer on the transaction.
pub fn transfer_spl_from_user<'a>(
    source: &'a AccountView,
    destination: &'a AccountView,
    authority: &'a AccountView, // User (must be signer on tx)
    token_program: &'a AccountView,
    amount: u64,
) -> ProgramResult {
    verbose_log!("Transferring {} tokens from user to vault...", amount);

    // SPL Token transfer instruction data
    // Instruction 3 = Transfer, followed by amount (8 bytes LE)
    let mut ix_data = [0u8; 9];
    ix_data[0] = 3; // Transfer instruction
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        InstructionAccount::writable(source.address()),
        InstructionAccount::writable(destination.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &ix_data,
    };

    let account_infos = [
        source,
        destination,
        authority,
        token_program,
    ];

    invoke(&instruction, &account_infos)
}

