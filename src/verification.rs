//! Security verification helpers for privacy swap program
//!
//! Provides PDA verification, account owner checks,
//! and CPI program verification (CVE-001 fix).

use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio_pubkey::derive_address;
use solana_program_log::log;

use crate::{
    error::PrivacySwapError,
    state::seeds_v2,
    ID,
};

// ============================================================
// KNOWN PROGRAM IDS (CVE-001 FIX)
// ============================================================
// These constants prevent attackers from passing fake programs
// that could steal funds by returning success without acting.

/// SPL Token Program ID
/// Address: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];

/// System Program ID
/// Address: 11111111111111111111111111111111
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Associated Token Account Program ID
/// Address: ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
pub const ATA_PROGRAM_ID: [u8; 32] = [
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1,
    0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84,
    0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
];

/// Light Protocol Compressed Token Program ID
/// Address: cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
pub const LIGHT_CTOKEN_PROGRAM_ID: [u8; 32] = [
    0x0a, 0x55, 0xd0, 0x10, 0x26, 0xef, 0xc0, 0x2c,
    0xb2, 0x8f, 0x80, 0x82, 0x30, 0x24, 0x05, 0x15,
    0x4c, 0x8b, 0x43, 0x6f, 0x53, 0xb5, 0xce, 0x0b,
    0x46, 0xf5, 0x00, 0xd8, 0x1b, 0x6e, 0x75, 0x83,
];

/// Meteora DAMM v2 (CP-AMM) Program ID
/// Address: cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG
pub const METEORA_DAMM_V2_PROGRAM_ID: [u8; 32] = [
    0x09, 0x2d, 0x21, 0x35, 0x65, 0x7a, 0x15, 0x9c,
    0x2b, 0x87, 0xd4, 0xb6, 0x6a, 0x70, 0xdb, 0x8e,
    0x97, 0x52, 0x38, 0x9f, 0xf7, 0x6a, 0xaf, 0x20,
    0x6c, 0xed, 0x06, 0x3a, 0x38, 0xf9, 0x5a, 0xed,
];

/// Meteora DLMM Program ID
/// Address: LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo
pub const METEORA_DLMM_PROGRAM_ID: [u8; 32] = [
    0x02, 0xf8, 0x4e, 0x66, 0x12, 0x5c, 0xd6, 0x3e,
    0x75, 0x1a, 0x9f, 0x58, 0x3f, 0x06, 0x96, 0x4b,
    0x14, 0x25, 0x38, 0x3d, 0x85, 0x97, 0xc9, 0x3d,
    0x26, 0x7f, 0x8d, 0x0c, 0x7c, 0x38, 0xd2, 0xb0,
];

/// Orca Whirlpools Program ID
/// Address: whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc
pub const ORCA_WHIRLPOOL_PROGRAM_ID: [u8; 32] = [
    0x0e, 0x7e, 0x43, 0x34, 0x86, 0xb2, 0x2c, 0x35,
    0xba, 0x5b, 0x1b, 0x13, 0x5a, 0x19, 0x08, 0xa4,
    0x69, 0x13, 0x95, 0x04, 0xe0, 0x0b, 0x6f, 0x8f,
    0x23, 0x42, 0x4a, 0x4e, 0x17, 0x3d, 0xd0, 0x03,
];

/// Raydium AMM V4 Program ID
/// Address: 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8
pub const RAYDIUM_AMM_V4_PROGRAM_ID: [u8; 32] = [
    0x04, 0xf5, 0x54, 0x03, 0xb8, 0xa2, 0x6a, 0x29,
    0xb2, 0xa0, 0x7b, 0xf7, 0x36, 0xae, 0x41, 0x94,
    0xe2, 0x8a, 0xf8, 0xc1, 0x9f, 0x97, 0x40, 0xfb,
    0x8c, 0x8b, 0x88, 0x47, 0xfe, 0xaa, 0x4c, 0x76,
];

/// Raydium CLMM Program ID
/// Address: CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK
pub const RAYDIUM_CLMM_PROGRAM_ID: [u8; 32] = [
    0x0a, 0x0a, 0x54, 0x67, 0xd5, 0x38, 0xb9, 0x3e,
    0x96, 0x5c, 0x39, 0x69, 0xf4, 0x97, 0x56, 0x7a,
    0x3a, 0xa5, 0x84, 0x02, 0x24, 0x64, 0x04, 0xb4,
    0xe1, 0x4d, 0x3a, 0xb1, 0xa8, 0x8e, 0x15, 0xd6,
];

/// Jupiter Aggregator V6 Program ID
/// Address: JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
pub const JUPITER_V6_PROGRAM_ID: [u8; 32] = [
    0x03, 0xbb, 0x9f, 0xf0, 0x8e, 0x35, 0x7b, 0x8b,
    0x57, 0x43, 0x80, 0x94, 0x3a, 0x30, 0x7e, 0xf9,
    0xcc, 0x47, 0x12, 0xdc, 0x15, 0x74, 0xd0, 0x05,
    0x7c, 0x32, 0xaf, 0x91, 0x75, 0x72, 0xea, 0xf4,
];

/// Clock Sysvar ID
/// Address: SysvarC1ock11111111111111111111111111111111
/// Used for reading current slot for timeout checks (HIGH-004 fix)
pub const CLOCK_SYSVAR_ID: [u8; 32] = [
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9,
    0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
    0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
    0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
];

// ============================================================
// CPI PROGRAM VERIFICATION FUNCTIONS (CVE-001 FIX)
// ============================================================

/// Verify the account is the SPL Token Program
///
/// SECURITY: Prevents attackers from passing a fake token program
/// that could return success without actually transferring tokens.
pub fn verify_spl_token_program(token_program: &AccountView) -> ProgramResult {
    if token_program.address().as_ref() != &SPL_TOKEN_PROGRAM_ID {
        log!("SECURITY: Invalid SPL Token program!");
        log!("  Expected: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the System Program
///
/// SECURITY: Prevents attackers from passing a fake system program
/// that could return success without actually creating accounts.
pub fn verify_system_program(system_program: &AccountView) -> ProgramResult {
    if system_program.address().as_ref() != &SYSTEM_PROGRAM_ID {
        log!("SECURITY: Invalid System program!");
        log!("  Expected: 11111111111111111111111111111111");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Associated Token Account Program
///
/// SECURITY: Prevents attackers from passing a fake ATA program
/// that could return success without actually creating token accounts.
pub fn verify_ata_program(ata_program: &AccountView) -> ProgramResult {
    if ata_program.address().as_ref() != &ATA_PROGRAM_ID {
        log!("SECURITY: Invalid ATA program!");
        log!("  Expected: ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Light Protocol Compressed Token Program
///
/// SECURITY: Prevents attackers from passing a fake cToken program
/// that could return success without decompressing/compressing tokens.
pub fn verify_light_ctoken_program(ctoken_program: &AccountView) -> ProgramResult {
    if ctoken_program.address().as_ref() != &LIGHT_CTOKEN_PROGRAM_ID {
        log!("SECURITY: Invalid Light cToken program!");
        log!("  Expected: cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Meteora DAMM v2 Program
///
/// SECURITY: Prevents attackers from passing a fake DEX program
/// that could return success without actually swapping tokens.
pub fn verify_meteora_program(dex_program: &AccountView) -> ProgramResult {
    if dex_program.address().as_ref() != &METEORA_DAMM_V2_PROGRAM_ID {
        log!("SECURITY: Invalid Meteora DAMM v2 program!");
        log!("  Expected: cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Meteora DLMM Program
pub fn verify_meteora_dlmm_program(dex_program: &AccountView) -> ProgramResult {
    if dex_program.address().as_ref() != &METEORA_DLMM_PROGRAM_ID {
        log!("SECURITY: Invalid Meteora DLMM program!");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Orca Whirlpools Program
pub fn verify_orca_program(dex_program: &AccountView) -> ProgramResult {
    if dex_program.address().as_ref() != &ORCA_WHIRLPOOL_PROGRAM_ID {
        log!("SECURITY: Invalid Orca Whirlpools program!");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Raydium AMM V4 Program
pub fn verify_raydium_amm_program(dex_program: &AccountView) -> ProgramResult {
    if dex_program.address().as_ref() != &RAYDIUM_AMM_V4_PROGRAM_ID {
        log!("SECURITY: Invalid Raydium AMM V4 program!");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Raydium CLMM Program
pub fn verify_raydium_clmm_program(dex_program: &AccountView) -> ProgramResult {
    if dex_program.address().as_ref() != &RAYDIUM_CLMM_PROGRAM_ID {
        log!("SECURITY: Invalid Raydium CLMM program!");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Jupiter Aggregator V6 Program
pub fn verify_jupiter_program(dex_program: &AccountView) -> ProgramResult {
    if dex_program.address().as_ref() != &JUPITER_V6_PROGRAM_ID {
        log!("SECURITY: Invalid Jupiter V6 program!");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Verify the account is the Clock Sysvar (HIGH-004 fix)
///
/// SECURITY: Used for timeout verification in refund_pending.
/// The Clock sysvar is a read-only sysvar provided by the runtime.
pub fn verify_clock_sysvar(clock_account: &AccountView) -> ProgramResult {
    if clock_account.address().as_ref() != &CLOCK_SYSVAR_ID {
        log!("SECURITY: Invalid Clock sysvar!");
        log!("  Expected: SysvarC1ock11111111111111111111111111111111");
        return Err(PrivacySwapError::InvalidProgram.into());
    }
    Ok(())
}

/// Read current slot from Clock sysvar data (HIGH-004 fix)
///
/// Clock sysvar layout (40 bytes total):
/// - slot: u64 (offset 0-8)
/// - epoch_start_timestamp: i64 (offset 8-16)
/// - epoch: u64 (offset 16-24)
/// - leader_schedule_epoch: u64 (offset 24-32)
/// - unix_timestamp: i64 (offset 32-40)
pub fn read_clock_slot(clock_data: &[u8]) -> Option<u64> {
    if clock_data.len() < 8 {
        return None;
    }
    let slot_bytes: [u8; 8] = clock_data[0..8].try_into().ok()?;
    Some(u64::from_le_bytes(slot_bytes))
}

/// Verify DEX program by type (for Keeper pattern)
/// Returns Ok if the provided program matches the expected DEX type
pub fn verify_dex_program_by_type(dex_program: &AccountView, dex_type: u8) -> ProgramResult {
    let program_bytes = dex_program.address().as_ref();

    let is_valid = match dex_type {
        0 => program_bytes == &METEORA_DAMM_V2_PROGRAM_ID,  // MeteoraDammV2
        1 => program_bytes == &METEORA_DLMM_PROGRAM_ID,     // MeteoraDlmm
        2 => program_bytes == &ORCA_WHIRLPOOL_PROGRAM_ID,   // OrcaWhirlpool
        3 => program_bytes == &RAYDIUM_CLMM_PROGRAM_ID,     // RaydiumClmm
        4 => program_bytes == &RAYDIUM_AMM_V4_PROGRAM_ID,   // RaydiumAmmV4
        5 => program_bytes == &JUPITER_V6_PROGRAM_ID,       // JupiterV6
        _ => false,
    };

    if !is_valid {
        log!("SECURITY: DEX program mismatch for dex_type {}!", dex_type);
        return Err(PrivacySwapError::InvalidProgram.into());
    }

    Ok(())
}

// CVE-001 FIX: Safe conversion from Address to [u8; 32]
// Previously used unsafe pointer cast which could break if Address layout changes
fn address_to_bytes(addr: &Address) -> [u8; 32] {
    // Use the safe as_ref() method which is guaranteed by the Address API
    let slice: &[u8] = addr.as_ref();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(slice);
    bytes
}

/// Verify vault PDA derivation
/// Seeds: ["vault", input_mint, output_mint, tier]
pub fn verify_vault_pda(
    vault_account: &AccountView,
    input_mint: &[u8],
    output_mint: &[u8],
    tier: u8,
    bump: u8,
) -> ProgramResult {
    let tier_bytes = [tier];

    let expected_address = derive_address::<4>(
        &[seeds_v2::VAULT, input_mint, output_mint, &tier_bytes],
        Some(bump),
        &address_to_bytes(&ID),
    );

    if vault_account.address().as_ref() != expected_address.as_ref() {
        log!("Vault PDA verification FAILED!");
        log!("  Expected: first 8 bytes of derived");
        log!("  Got: account address mismatch");
        return Err(PrivacySwapError::InvalidPda.into());
    }

    Ok(())
}

/// Verify commitment account PDA derivation
/// Seeds: ["commitment", commitment_hash]
pub fn verify_commitment_pda(
    commitment_account: &AccountView,
    commitment_hash: &[u8; 32],
    bump: u8,
) -> ProgramResult {
    let expected_address = derive_address::<2>(
        &[seeds_v2::COMMITMENT, commitment_hash],
        Some(bump),
        &address_to_bytes(&ID),
    );

    if commitment_account.address().as_ref() != expected_address.as_ref() {
        log!("Commitment PDA verification FAILED!");
        return Err(PrivacySwapError::InvalidPda.into());
    }

    Ok(())
}

/// Verify nullifier registry PDA derivation
/// Seeds: ["nullifier", pool]
pub fn verify_nullifier_pda(
    nullifier_account: &AccountView,
    pool: &[u8; 32],
    bump: u8,
) -> ProgramResult {
    let expected_address = derive_address::<2>(
        &[seeds_v2::NULLIFIER, pool],
        Some(bump),
        &address_to_bytes(&ID),
    );

    if nullifier_account.address().as_ref() != expected_address.as_ref() {
        log!("Nullifier PDA verification FAILED!");
        return Err(PrivacySwapError::InvalidPda.into());
    }

    Ok(())
}

/// Verify pool config PDA derivation
/// Seeds: ["privacy_pool", input_mint, output_mint, tier]
pub fn verify_pool_config_pda(
    pool_config: &AccountView,
    input_mint: &[u8],
    output_mint: &[u8],
    tier: u8,
    bump: u8,
) -> ProgramResult {
    let tier_bytes = [tier];

    let expected_address = derive_address::<4>(
        &[seeds_v2::PRIVACY_POOL, input_mint, output_mint, &tier_bytes],
        Some(bump),
        &address_to_bytes(&ID),
    );

    if pool_config.address().as_ref() != expected_address.as_ref() {
        log!("Pool config PDA verification FAILED!");
        return Err(PrivacySwapError::InvalidPda.into());
    }

    Ok(())
}

/// Verify account is owned by this program
/// SAFETY: Uses unsafe owner() call which is valid for all accounts
pub fn verify_program_owner(
    account: &AccountView,
    program_id: &Address,
) -> ProgramResult {
    // SAFETY: owner() is safe to call on valid accounts passed to the program
    let owner = unsafe { account.owner() };

    if owner != program_id {
        log!("Account owner verification FAILED!");
        log!("  Expected: program ID");
        return Err(PrivacySwapError::InvalidOwner.into());
    }

    Ok(())
}

/// MED-001 FIX: Verify accounts are distinct (no duplicates)
///
/// SECURITY: Prevents attackers from passing the same account for multiple parameters.
/// This could cause issues like:
/// - vault_output_ata == destination_ata: Self-transfer, no net change
/// - vault_output_ata == fee_wallet_ata: Fee goes to vault instead of protocol
/// - Could cause accounting inconsistencies
///
/// Usage: Call with pairs of accounts that must be distinct:
/// ```rust
/// verify_distinct_accounts(&[
///     (source, dest, "source and destination"),
///     (vault, fee, "vault and fee wallet"),
/// ])?;
/// ```
pub fn verify_distinct_accounts(pairs: &[(&AccountView, &AccountView, &str)]) -> ProgramResult {
    for (account_a, account_b, description) in pairs {
        if account_a.address() == account_b.address() {
            log!("SECURITY: Duplicate accounts detected!");
            log!("  Accounts must be distinct: {}", *description);
            return Err(PrivacySwapError::DuplicateAccount.into());
        }
    }
    Ok(())
}
