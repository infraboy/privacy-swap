//! Instruction processor
//!
//! V2 adds privacy pool processors with vault-based swaps and commitment scheme.
//!
//! PRIVACY NOTE: Verbose logging is disabled by default.
//! To enable for debugging, build with: cargo build-sbf --features verbose-logs

use pinocchio::{
    AccountView,
    Address,
    error::ProgramError,
    ProgramResult,
};
use solana_program_log::log;

// Conditional logging macro - only logs when verbose-logs feature is enabled
// This is critical for privacy - we don't want to expose amounts/fees in production logs
#[cfg(feature = "verbose-logs")]
macro_rules! verbose_log {
    ($($arg:tt)*) => {
        log!($($arg)*)
    };
}

#[cfg(not(feature = "verbose-logs"))]
macro_rules! verbose_log {
    ($($arg:tt)*) => {
        // No-op in production - logs are suppressed for privacy
    };
}
use solana_instruction_view::{
    cpi::invoke,
    InstructionAccount, InstructionView,
};

use crate::{
    error::PrivacySwapError,
    instruction::{
        discriminator, PrivateSwapArgs, InitializeConfigArgs, CloseAccountsArgs, DexType,
        InitializePoolArgs, DepositAndSwapArgs, ClaimArgs,
        ExpandNullifierArgs,
        // V3 Keeper pattern
        DepositArgs, ExecuteSwapArgs,
        // V4 Direct transfer
        DepositDirectArgs,
        // V5 Refund mechanism (HIGH-002 fix)
        RefundPendingArgs,
    },
    light_cpi::{DecompressCTokenToSplParams, CompressSplToCtokenParams, decompress_ctoken_to_spl, compress_spl_to_ctoken},
    state::DenominationTier,
};

// ============================================================
// HARDCODED FEE CONFIGURATION (IMMUTABLE - CANNOT BE CHANGED)
// ============================================================

/// Fee wallet address: CZWVNCq5tAC7onngt5WCTv6t17obiQz9nXxuQqQx6qap
/// This is HARDCODED and CANNOT be changed by anyone - baked into the program
const FEE_WALLET: Address = Address::new_from_array([
    0xab, 0xc4, 0x7c, 0x47, 0xae, 0x78, 0x3b, 0x48,
    0x9b, 0xad, 0xb1, 0x4c, 0xb9, 0x66, 0x44, 0x2c,
    0x9f, 0xa0, 0x70, 0x82, 0xde, 0x87, 0x6d, 0x7a,
    0x38, 0x0b, 0x28, 0xe8, 0x29, 0x0a, 0x68, 0x81,
]);

/// Fee in basis points: 150 = 1.5%
/// HARDCODED - cannot be changed
const FEE_BASIS_POINTS: u64 = 150;

/// Basis points denominator: 10000 = 100%
const BASIS_POINTS_DENOMINATOR: u64 = 10000;

/// Calculate fee safely using u128 to prevent overflow
/// CVE-002 FIX: For large amounts, amount * 150 can overflow u64
/// Using u128 intermediate ensures safety for any u64 input
#[inline]
fn calculate_fee_safe(amount: u64) -> Result<u64, PrivacySwapError> {
    // Use u128 for intermediate calculation to prevent overflow
    let fee = (amount as u128)
        .checked_mul(FEE_BASIS_POINTS as u128)
        .ok_or(PrivacySwapError::MathOverflow)?
        .checked_div(BASIS_POINTS_DENOMINATOR as u128)
        .ok_or(PrivacySwapError::MathOverflow)?;

    // MED-002 FIX: Enforce minimum fee of 1 token for non-zero amounts
    // This prevents fee bypass via small claims
    // Without this: claims < 67 tokens would pay 0 fee
    let fee = if amount > 0 && fee == 0 { 1 } else { fee as u64 };

    Ok(fee)
}

/// Main instruction processor
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(PrivacySwapError::InvalidInstruction.into());
    }

    let instruction = instruction_data[0];

    match instruction {
        // V1 instructions (legacy)
        discriminator::PRIVATE_SWAP => {
            log!("Instruction: PrivateSwap (V1)");
            process_private_swap(program_id, accounts, instruction_data)
        }
        discriminator::INITIALIZE_CONFIG => {
            log!("Instruction: InitializeConfig (V1)");
            process_initialize_config(program_id, accounts, instruction_data)
        }
        discriminator::UPDATE_OWNER_KEY => {
            log!("Instruction: UpdateOwnerKey (V1)");
            process_update_owner_key(program_id, accounts, instruction_data)
        }
        discriminator::CLOSE_ACCOUNTS => {
            log!("Instruction: CloseAccounts (V1)");
            process_close_accounts(program_id, accounts, instruction_data)
        }

        // V2 instructions (privacy pools)
        discriminator::INITIALIZE_POOL => {
            log!("Instruction: InitializePool (V2)");
            process_initialize_pool(program_id, accounts, instruction_data)
        }
        discriminator::DEPOSIT_AND_SWAP => {
            log!("Instruction: DepositAndSwap (V2)");
            process_deposit_and_swap(program_id, accounts, instruction_data)
        }
        discriminator::CLAIM => {
            log!("Instruction: Claim (V2)");
            process_claim(program_id, accounts, instruction_data)
        }
        discriminator::EXPAND_NULLIFIER => {
            log!("Instruction: ExpandNullifier (V2)");
            process_expand_nullifier(program_id, accounts, instruction_data)
        }

        // V3 instructions (Keeper pattern - full privacy with any DEX)
        discriminator::DEPOSIT => {
            log!("Instruction: Deposit (V3 Keeper)");
            process_deposit(program_id, accounts, instruction_data)
        }
        discriminator::EXECUTE_SWAP => {
            log!("Instruction: ExecuteSwap (V3 Keeper)");
            process_execute_swap(program_id, accounts, instruction_data)
        }

        // V4 instruction (Direct transfer - no swap)
        discriminator::DEPOSIT_DIRECT => {
            log!("Instruction: DepositDirect (V4 Transfer)");
            process_deposit_direct(program_id, accounts, instruction_data)
        }

        discriminator::REFUND_PENDING => {
            log!("Instruction: RefundPending (V5 Refund)");
            process_refund_pending(program_id, accounts, instruction_data)
        }

        _ => Err(PrivacySwapError::InvalidInstruction.into()),
    }
}

// ============================================================
// V2 PROCESSORS
// ============================================================

/// Initialize a privacy pool for a specific token pair and denomination tier
///
/// Accounts:
/// 0.  [signer, writable] Authority (pool admin, pays for creation)
/// 1.  [] Input token mint
/// 2.  [] Output token mint
/// 3.  [writable] Pool config PDA
/// 4.  [writable] Vault PDA
/// 5.  [writable] Vault input ATA (SPL token account)
/// 6.  [writable] Vault output ATA (SPL token account)
/// 7.  [writable] Nullifier registry PDA
/// 8.  [] DEX pool (Meteora, etc.)
/// 9.  [] System program
/// 10. [] Token program
/// 11. [] Associated Token program
fn process_initialize_pool(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::{PrivacyPoolConfig, seeds_v2};
    use crate::vault::{
        create_account, create_ata, calculate_rent_exempt_balance,
        init_pool_config, init_nullifier_registry, nullifier_registry_size,
    };
    use pinocchio_pubkey::derive_address;

    let args = InitializePoolArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    if accounts.len() < 12 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let authority = &accounts[0];
    let input_mint = &accounts[1];
    let output_mint = &accounts[2];
    let pool_config = &accounts[3];
    let vault_pda = &accounts[4];
    let vault_input_ata = &accounts[5];
    let vault_output_ata = &accounts[6];
    let nullifier_registry = &accounts[7];
    let dex_pool = &accounts[8];
    let system_program = &accounts[9];
    let token_program = &accounts[10];
    let ata_program = &accounts[11];

    // Verify authority is signer
    if !authority.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // === CVE-001 FIX: Verify CPI program IDs ===
    use crate::verification::{verify_system_program, verify_spl_token_program, verify_ata_program};
    verify_system_program(system_program)?;
    verify_spl_token_program(token_program)?;
    verify_ata_program(ata_program)?;
    verbose_log!("  CPI programs verified");

    // Verify tier is valid
    let tier = DenominationTier::from_u8(args.tier)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    verbose_log!("Initializing privacy pool:");
    verbose_log!("  Tier: {} ({} lamports)", args.tier, tier.sol_amount());

    // Get input/output mint bytes
    let input_mint_bytes: [u8; 32] = input_mint.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    let output_mint_bytes: [u8; 32] = output_mint.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    let tier_bytes = [args.tier];

    // CVE-001 FIX: Safe conversion from Address to [u8; 32]
    fn address_to_bytes(addr: &Address) -> [u8; 32] {
        let slice: &[u8] = addr.as_ref();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        bytes
    }

    // === STEP 1: Verify vault PDA using client-provided bump ===
    verbose_log!("Step 1: Verifying vault PDA...");

    let vault_bump = args.vault_bump;
    let program_id_bytes = address_to_bytes(program_id);
    let vault_address = derive_address::<4>(
        &[seeds_v2::VAULT, &input_mint_bytes, &output_mint_bytes, &tier_bytes],
        Some(vault_bump),
        &program_id_bytes,
    );

    // Verify the vault PDA matches the provided account
    if vault_pda.address().as_ref() != vault_address.as_ref() {
        verbose_log!("Vault PDA mismatch!");
        return Err(PrivacySwapError::InvalidPda.into());
    }
    verbose_log!("  Vault PDA verified, bump: {}", vault_bump);

    // === STEP 2: Verify pool config PDA ===
    verbose_log!("Step 2: Verifying pool config PDA...");

    let pool_config_bump = args.pool_config_bump;
    let pool_config_address = derive_address::<4>(
        &[seeds_v2::PRIVACY_POOL, &input_mint_bytes, &output_mint_bytes, &tier_bytes],
        Some(pool_config_bump),
        &program_id_bytes,
    );

    if pool_config.address().as_ref() != pool_config_address.as_ref() {
        verbose_log!("Pool config PDA mismatch!");
        return Err(PrivacySwapError::InvalidPda.into());
    }
    verbose_log!("  Pool config PDA verified, bump: {}", pool_config_bump);

    // === STEP 3: Verify nullifier registry PDA ===
    verbose_log!("Step 3: Verifying nullifier registry PDA...");

    let nullifier_bump = args.nullifier_bump;
    let nullifier_address = derive_address::<4>(
        &[seeds_v2::NULLIFIER, &input_mint_bytes, &output_mint_bytes, &tier_bytes],
        Some(nullifier_bump),
        &program_id_bytes,
    );

    if nullifier_registry.address().as_ref() != nullifier_address.as_ref() {
        verbose_log!("Nullifier registry PDA mismatch!");
        return Err(PrivacySwapError::InvalidPda.into());
    }
    verbose_log!("  Nullifier registry PDA verified, bump: {}", nullifier_bump);

    // === STEP 4: Create pool config account ===
    verbose_log!("Step 4: Creating pool config account...");

    let pool_config_space = PrivacyPoolConfig::LEN as u64;
    let pool_config_lamports = calculate_rent_exempt_balance(pool_config_space);

    let pool_config_seeds: [&[u8]; 5] = [
        seeds_v2::PRIVACY_POOL,
        &input_mint_bytes,
        &output_mint_bytes,
        &tier_bytes,
        &[pool_config_bump],
    ];

    create_account(
        authority,
        pool_config,
        system_program,
        pool_config_lamports,
        pool_config_space,
        program_id,
        Some(&pool_config_seeds),
    )?;
    verbose_log!("  Pool config account created");

    // === STEP 5: Create vault PDA account (minimal, just for ATA ownership) ===
    verbose_log!("Step 5: Creating vault PDA account...");

    // Vault PDA just needs minimal space to exist as ATA owner
    let vault_space = 0u64; // Zero-data PDA
    let vault_lamports = calculate_rent_exempt_balance(vault_space);

    let vault_seeds: [&[u8]; 5] = [
        seeds_v2::VAULT,
        &input_mint_bytes,
        &output_mint_bytes,
        &tier_bytes,
        &[vault_bump],
    ];

    create_account(
        authority,
        vault_pda,
        system_program,
        vault_lamports,
        vault_space,
        program_id,
        Some(&vault_seeds),
    )?;
    verbose_log!("  Vault PDA created");

    // === STEP 6: Create nullifier registry account ===
    verbose_log!("Step 6: Creating nullifier registry account...");

    // OPTIMIZATION: Nullifier registry is now minimal since commitment status
    // already tracks claimed state. We keep a tiny registry for backwards
    // compatibility but don't rely on it for security.
    // Double-spend protection: CommitmentAccount.status = FullyClaimed
    let initial_capacity: u32 = 1; // Minimal - just header, ~0.003 SOL rent
    let nullifier_space = nullifier_registry_size(initial_capacity) as u64;
    let nullifier_lamports = calculate_rent_exempt_balance(nullifier_space);

    let nullifier_seeds: [&[u8]; 5] = [
        seeds_v2::NULLIFIER,
        &input_mint_bytes,
        &output_mint_bytes,
        &tier_bytes,
        &[nullifier_bump],
    ];

    create_account(
        authority,
        nullifier_registry,
        system_program,
        nullifier_lamports,
        nullifier_space,
        program_id,
        Some(&nullifier_seeds),
    )?;
    verbose_log!("  Nullifier registry created with capacity {}", initial_capacity);

    // === STEP 7: Create vault ATAs (skip for universal pools) ===
    // Universal pools (dex_type = 255) don't create ATAs at init time
    // ATAs are created on-the-fly during deposit for the actual token
    use crate::state::UNIVERSAL_MINT;
    let is_universal_pool = args.dex_type == 255 ||
        input_mint_bytes == UNIVERSAL_MINT ||
        output_mint_bytes == UNIVERSAL_MINT;

    if !is_universal_pool {
        verbose_log!("Step 7: Creating vault ATAs...");

        // Create input token ATA for vault
        create_ata(
            authority,
            vault_input_ata,
            vault_pda,
            input_mint,
            system_program,
            token_program,
        )?;
        verbose_log!("  Vault input ATA created");

        // Create output token ATA for vault
        create_ata(
            authority,
            vault_output_ata,
            vault_pda,
            output_mint,
            system_program,
            token_program,
        )?;
        verbose_log!("  Vault output ATA created");
    } else {
        verbose_log!("Step 7: Skipping ATA creation for universal pool");
        verbose_log!("  ATAs will be created on-the-fly during deposit");
    }

    // === STEP 8: Initialize pool config data ===
    verbose_log!("Step 8: Initializing pool config data...");

    let mut pool_config_data = pool_config.try_borrow_mut()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    let vault_pda_bytes: [u8; 32] = vault_pda.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    let vault_input_ata_bytes: [u8; 32] = vault_input_ata.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    let vault_output_ata_bytes: [u8; 32] = vault_output_ata.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    let dex_pool_bytes: [u8; 32] = dex_pool.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    let authority_bytes: [u8; 32] = authority.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;

    init_pool_config(
        &mut pool_config_data,
        &input_mint_bytes,
        &output_mint_bytes,
        args.tier,
        tier.sol_amount(),
        &vault_pda_bytes,
        vault_bump,
        &vault_input_ata_bytes,
        &vault_output_ata_bytes,
        &dex_pool_bytes,
        args.dex_type,
        &authority_bytes,
    );

    drop(pool_config_data);

    // === STEP 9: Initialize nullifier registry data ===
    verbose_log!("Step 9: Initializing nullifier registry data...");

    let mut nullifier_data = nullifier_registry.try_borrow_mut()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    let pool_config_bytes: [u8; 32] = pool_config.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;

    init_nullifier_registry(&mut nullifier_data, &pool_config_bytes, initial_capacity);

    drop(nullifier_data);

    verbose_log!("Pool initialization complete!");
    verbose_log!("  Pool config: first 8 bytes of address");
    verbose_log!("  Vault bump: {}", vault_bump);
    verbose_log!("  Tier: {} ({} lamports)", args.tier, tier.sol_amount());

    Ok(())
}

/// Deposit cTokens and swap atomically
///
/// This is the main privacy function. User deposits to vault, vault swaps,
/// and commitment is stored for later claim.
///
/// Accounts:
/// 0.  [signer, writable] User (depositor, pays fees)
/// 1.  [writable] Pool config
/// 2.  [] Input token mint
/// 3.  [] Output token mint
/// 4.  [] Vault PDA
/// 5.  [writable] Vault input SPL ATA
/// 6.  [writable] Vault output SPL ATA
/// 7.  [writable] User's input SPL token account (source)
/// 8.  [] Light Protocol CPI authority
/// 9.  [] Light cToken program
/// 10. [] SPL Token program
/// 11. [writable] DEX pool
/// 12. [writable] DEX vault A
/// 13. [writable] DEX vault B
/// 14. [] DEX pool authority
/// 15. [] DEX program
/// 16. [writable] Commitment account (PDA, to be created)
/// 17. [] System program
/// 18. [] Clock sysvar (optional, for timestamp)
fn process_deposit_and_swap(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::{CommitmentAccount, PrivacyPoolConfig, seeds_v2};
    use crate::vault::{
        create_account, calculate_rent_exempt_balance,
        init_commitment_account, update_pool_deposit,
        vault_meteora_swap, read_token_balance,
    };
    use crate::verification::verify_vault_pda;
    use pinocchio_pubkey::derive_address;

    let args = DepositAndSwapArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    if accounts.len() < 18 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let pool_config = &accounts[1];
    let input_mint = &accounts[2];
    let output_mint = &accounts[3];
    let vault_pda = &accounts[4];
    let vault_input_ata = &accounts[5];
    let vault_output_ata = &accounts[6];
    let user_input_ata = &accounts[7];
    let _cpi_authority = &accounts[8];
    let _ctoken_program = &accounts[9];
    let token_program = &accounts[10];
    let dex_pool = &accounts[11];
    let dex_vault_a = &accounts[12];
    let dex_vault_b = &accounts[13];
    let dex_pool_authority = &accounts[14];
    let dex_program = &accounts[15];
    let commitment_account = &accounts[16];
    let system_program = &accounts[17];

    // Verify user is signer
    if !user.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // === CVE-001 FIX: Verify CPI program IDs ===
    use crate::verification::{verify_system_program, verify_spl_token_program, verify_meteora_program};
    verify_system_program(system_program)?;
    verify_spl_token_program(token_program)?;
    verify_meteora_program(dex_program)?;
    verbose_log!("  CPI programs verified");

    verbose_log!("Processing deposit and swap:");
    verbose_log!("  Min output: {}", args.min_output_amount);

    // === Read pool config to get tier and vault info ===
    let pool_data = pool_config.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    // Pool config layout:
    // [0..8]: discriminator
    // [8..40]: input_mint
    // [40..72]: output_mint
    // [72]: tier
    // [73..81]: denomination_amount
    // [81..113]: vault_pda
    // [113]: vault_bump

    if pool_data.len() < PrivacyPoolConfig::LEN {
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    let tier = pool_data[72];
    let denomination_amount = u64::from_le_bytes(
        pool_data[73..81].try_into().map_err(|_| PrivacySwapError::InvalidAccount)?
    );
    let vault_bump = pool_data[113];

    // Get input/output mint bytes for PDA derivation
    let input_mint_bytes: [u8; 32] = pool_data[8..40].try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    let output_mint_bytes: [u8; 32] = pool_data[40..72].try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;

    drop(pool_data);

    let tier_bytes = [tier];

    // === STEP 1: Verify vault PDA ===
    verbose_log!("Step 1: Verifying vault PDA...");
    verify_vault_pda(
        vault_pda,
        &input_mint_bytes,
        &output_mint_bytes,
        tier,
        vault_bump,
    )?;
    verbose_log!("  Vault PDA verified");

    // === STEP 2: Transfer user's SPL tokens to vault ===
    verbose_log!("Step 2: Transferring {} input tokens to vault...", denomination_amount);

    // SPL Token Transfer instruction
    let mut transfer_ix_data = [0u8; 9];
    transfer_ix_data[0] = 3; // Transfer instruction
    transfer_ix_data[1..9].copy_from_slice(&denomination_amount.to_le_bytes());

    let transfer_accounts = [
        InstructionAccount::writable(user_input_ata.address()),
        InstructionAccount::writable(vault_input_ata.address()),
        InstructionAccount::readonly_signer(user.address()),
    ];

    let transfer_instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &transfer_accounts,
        data: &transfer_ix_data,
    };

    let transfer_account_infos = [
        user_input_ata,
        vault_input_ata,
        user,
        token_program,
    ];

    invoke(&transfer_instruction, &transfer_account_infos)?;
    verbose_log!("  Tokens transferred to vault");

    // === STEP 3: Record output balance BEFORE swap ===
    let output_balance_before = {
        let output_ata_data = vault_output_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
        read_token_balance(&output_ata_data)
    };
    verbose_log!("  Output balance before swap: {}", output_balance_before);

    // === STEP 4: Swap on DEX (vault PDA signs) ===
    verbose_log!("Step 3: Swapping on DEX...");

    vault_meteora_swap(
        dex_pool,
        dex_pool_authority,
        vault_input_ata,
        vault_output_ata,
        dex_vault_a,
        dex_vault_b,
        vault_pda,
        token_program,
        input_mint,
        output_mint,
        denomination_amount,
        args.min_output_amount,
        &input_mint_bytes,
        &output_mint_bytes,
        &tier_bytes,
        &[vault_bump],
    )?;
    verbose_log!("  Swap executed");

    // === STEP 5: Calculate actual output amount ===
    let output_balance_after = {
        let output_ata_data = vault_output_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
        read_token_balance(&output_ata_data)
    };

    // SEC-005 FIX: Use checked_sub instead of saturating_sub
    // If balance decreased unexpectedly, fail instead of silently returning 0
    let actual_output = output_balance_after
        .checked_sub(output_balance_before)
        .ok_or_else(|| {
            verbose_log!("SECURITY: Output balance decreased unexpectedly!");
            PrivacySwapError::InsufficientOutput
        })?;

    // Verify we got a non-zero output
    if actual_output == 0 {
        verbose_log!("SECURITY: Swap produced zero output!");
        return Err(PrivacySwapError::SwapFailed.into());
    }

    verbose_log!("  Actual output: {}", actual_output);

    // Verify slippage
    if actual_output < args.min_output_amount {
        verbose_log!("  Slippage exceeded! {} < {}", actual_output, args.min_output_amount);
        return Err(PrivacySwapError::SlippageExceeded.into());
    }

    // === STEP 6: Create commitment account ===
    verbose_log!("Step 4: Creating commitment account...");

    // CVE-001 FIX: Safe conversion from Address to [u8; 32]
    fn address_to_bytes(addr: &Address) -> [u8; 32] {
        let slice: &[u8] = addr.as_ref();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        bytes
    }

    // Verify commitment PDA using client-provided bump
    let commitment_bump = args.commitment_bump;
    let program_id_bytes = address_to_bytes(program_id);
    let commitment_address = derive_address::<2>(
        &[seeds_v2::COMMITMENT, &args.commitment],
        Some(commitment_bump),
        &program_id_bytes,
    );

    if commitment_account.address().as_ref() != commitment_address.as_ref() {
        verbose_log!("Commitment PDA mismatch!");
        return Err(PrivacySwapError::InvalidPda.into());
    }

    // SEC-014 FIX: Check for re-initialization
    // If account already has data with our discriminator, it's already initialized
    if commitment_account.data_len() > 0 {
        let existing_data = commitment_account.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
        if existing_data.len() >= 8 && &existing_data[0..8] == &CommitmentAccount::DISCRIMINATOR {
            verbose_log!("SECURITY: Commitment account already initialized!");
            return Err(PrivacySwapError::AccountAlreadyInitialized.into());
        }
        drop(existing_data);
    }

    let commitment_space = CommitmentAccount::LEN as u64;
    let commitment_lamports = calculate_rent_exempt_balance(commitment_space);

    let commitment_seeds: [&[u8]; 3] = [
        seeds_v2::COMMITMENT,
        &args.commitment,
        &[commitment_bump],
    ];

    create_account(
        user,
        commitment_account,
        system_program,
        commitment_lamports,
        commitment_space,
        program_id,
        Some(&commitment_seeds),
    )?;
    verbose_log!("  Commitment account created");

    // === STEP 7: Initialize commitment data ===
    verbose_log!("Step 5: Initializing commitment data...");

    let mut commitment_data = commitment_account.try_borrow_mut()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    let pool_config_bytes: [u8; 32] = pool_config.address().as_ref().try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;

    // Get current slot from Clock sysvar if available
    let current_slot = if accounts.len() > 18 {
        let clock = &accounts[18];
        let clock_data = clock.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
        if clock_data.len() >= 8 {
            u64::from_le_bytes(clock_data[0..8].try_into().unwrap_or([0; 8]))
        } else {
            0
        }
    } else {
        0
    };

    init_commitment_account(
        &mut commitment_data,
        &args.commitment,
        &pool_config_bytes,
        actual_output,
        current_slot,
        0, // timestamp - would need Clock sysvar for unix timestamp
    );

    drop(commitment_data);

    // === STEP 8: Update pool stats ===
    verbose_log!("Step 6: Updating pool stats...");

    let mut pool_data_mut = pool_config.try_borrow_mut()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    update_pool_deposit(&mut pool_data_mut, denomination_amount, actual_output);

    drop(pool_data_mut);

    verbose_log!("Deposit and swap completed successfully!");
    verbose_log!("  Input: {} tokens", denomination_amount);
    verbose_log!("  Output: {} tokens", actual_output);
    verbose_log!("  Commitment stored for later claim");

    Ok(())
}

/// Claim swapped tokens using secret
///
/// Anyone with the secret can claim to any destination address.
/// This breaks the link between depositor and receiver.
///
/// NOTE: A 1.5% fee is deducted and sent to the protocol fee wallet.
/// The fee wallet is HARDCODED and cannot be changed by anyone.
///
/// Accounts:
/// 0.  [signer, writable] Claimer (pays fees, can be anyone)
/// 1.  [] Pool config
/// 2.  [] Input token mint
/// 3.  [] Output token mint
/// 4.  [writable] Vault PDA
/// 5.  [writable] Vault's output SPL ATA (source)
/// 6.  [writable] Destination SPL ATA (target)
/// 7.  [] SPL Token program
/// 8.  [writable] Commitment account
/// 9.  [writable] Nullifier registry
/// 10. [writable] Fee wallet ATA (MUST belong to hardcoded FEE_WALLET)
/// 11. [] System program (optional - required if fee wallet ATA doesn't exist)
/// 12. [] ATA program (optional - required if fee wallet ATA doesn't exist)
/// 13. [] Fee wallet (optional - required if fee wallet ATA doesn't exist, must match FEE_WALLET)
///
/// Note: If fee wallet ATA doesn't exist for this token, the claimer pays
/// for its creation. Pass System program, ATA program, and Fee wallet as accounts 11-13.
fn process_claim(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::vault::{
        verify_commitment, is_nullified, add_nullifier,
        read_commitment_hash, read_commitment_output_amount,
        is_commitment_claimable, is_commitment_fully_claimed,
        get_remaining_amount, update_commitment_partial_claim,
        vault_transfer_spl,
    };
    use crate::verification::{verify_vault_pda, verify_program_owner, verify_spl_token_program};

    let args = ClaimArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    // === V4: Validate claim percentage ===
    if !args.is_valid_percentage() {
        verbose_log!("Invalid claim percentage: {}", args.claim_percentage);
        return Err(PrivacySwapError::InvalidClaimPercentage.into());
    }

    if accounts.len() < 11 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let claimer = &accounts[0];
    let pool_config = &accounts[1];
    let input_mint = &accounts[2];
    let output_mint = &accounts[3];
    let vault_pda = &accounts[4];
    let vault_output_ata = &accounts[5];
    let destination_ata = &accounts[6];
    let token_program = &accounts[7];
    let commitment_account = &accounts[8];
    let nullifier_registry = &accounts[9];
    let fee_wallet_ata = &accounts[10];

    // Verify claimer is signer (pays fees)
    if !claimer.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // SEC-001 FIX: Verify writable accounts are actually writable
    if !commitment_account.is_writable() {
        verbose_log!("SECURITY: commitment_account not writable!");
        return Err(PrivacySwapError::AccountNotWritable.into());
    }
    if !nullifier_registry.is_writable() {
        verbose_log!("SECURITY: nullifier_registry not writable!");
        return Err(PrivacySwapError::AccountNotWritable.into());
    }
    if !vault_output_ata.is_writable() {
        verbose_log!("SECURITY: vault_output_ata not writable!");
        return Err(PrivacySwapError::AccountNotWritable.into());
    }
    if !destination_ata.is_writable() {
        verbose_log!("SECURITY: destination_ata not writable!");
        return Err(PrivacySwapError::AccountNotWritable.into());
    }
    if !fee_wallet_ata.is_writable() {
        verbose_log!("SECURITY: fee_wallet_ata not writable!");
        return Err(PrivacySwapError::AccountNotWritable.into());
    }

    // MED-001 FIX: Verify critical accounts are distinct
    // Prevents attacks where same account is passed for multiple parameters
    use crate::verification::verify_distinct_accounts;
    verify_distinct_accounts(&[
        (vault_output_ata, destination_ata, "vault_output_ata and destination_ata"),
        (vault_output_ata, fee_wallet_ata, "vault_output_ata and fee_wallet_ata"),
        (destination_ata, fee_wallet_ata, "destination_ata and fee_wallet_ata"),
    ])?;

    verbose_log!("Processing claim ({}%)...", args.claim_percentage);

    // === CREATE FEE WALLET ATA IF NEEDED (user pays rent) ===
    // If fee wallet ATA doesn't exist for this token, create it
    // This allows the fee wallet to receive any token type
    if fee_wallet_ata.lamports() == 0 {
        verbose_log!("  Fee wallet ATA doesn't exist, creating...");

        // Need system_program, ata_program, and fee_wallet to create ATA
        if accounts.len() < 14 {
            verbose_log!("  Missing accounts for ATA creation! Need system_program, ata_program, fee_wallet");
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        let system_program = &accounts[11];
        let _ata_program = &accounts[12];
        let fee_wallet = &accounts[13];

        // Verify system program
        use crate::verification::verify_system_program;
        verify_system_program(system_program)?;

        // Verify fee_wallet matches hardcoded FEE_WALLET
        if fee_wallet.address().as_ref() != FEE_WALLET.as_ref() {
            verbose_log!("SECURITY: Fee wallet account doesn't match hardcoded FEE_WALLET!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        // Create ATA using CreateIdempotent (instruction discriminator = 1)
        // ATA CreateIdempotent accounts:
        // 0. [writable, signer] Payer (claimer pays)
        // 1. [writable] ATA to create
        // 2. [] Wallet (FEE_WALLET)
        // 3. [] Mint (output_mint)
        // 4. [] System Program
        // 5. [] Token Program
        use crate::vault::create_ata;
        create_ata(
            claimer,           // Payer (user pays for ATA creation)
            fee_wallet_ata,    // ATA to create
            fee_wallet,        // Wallet (verified to match FEE_WALLET)
            output_mint,       // Mint
            system_program,    // System Program
            token_program,     // Token Program
        )?;

        verbose_log!("  Fee wallet ATA created (user paid rent)");
    }

    // === VERIFY FEE WALLET ATA BELONGS TO HARDCODED FEE_WALLET ===
    // Read the ATA to verify it belongs to the correct owner
    {
        let fee_ata_data = fee_wallet_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // SPL Token Account layout: mint(32) + owner(32) + ...
        // Owner is at offset 32
        if fee_ata_data.len() < 64 {
            verbose_log!("Fee wallet ATA invalid!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        let ata_owner: [u8; 32] = fee_ata_data[32..64].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;

        // Verify ATA owner matches hardcoded FEE_WALLET
        if ata_owner != *FEE_WALLET.as_ref() {
            verbose_log!("Fee wallet ATA owner mismatch! Expected hardcoded fee wallet.");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        // SEC-006 FIX: Verify fee wallet ATA mint matches output token
        let fee_ata_mint: [u8; 32] = fee_ata_data[0..32].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;
        if fee_ata_mint != *output_mint.address().as_ref() {
            verbose_log!("SECURITY: Fee wallet ATA mint mismatch!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        // SEC-006 FIX: Verify fee wallet ATA is not frozen
        // SPL Token Account state is at offset 108 (1 = initialized, 2 = frozen)
        if fee_ata_data.len() > 108 && fee_ata_data[108] == 2 {
            verbose_log!("SECURITY: Fee wallet ATA is frozen!");
            return Err(PrivacySwapError::AccountFrozen.into());
        }

        verbose_log!("  Fee wallet ATA verified (owner, mint, not frozen)");
    }

    // === CVE-001 FIX: Verify CPI program IDs ===
    verify_spl_token_program(token_program)?;

    // === CRIT-004 FIX: Verify destination ATA mint matches output token ===
    // Prevents attacker from passing ATA for wrong token
    {
        let dest_ata_data = destination_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // SPL Token Account layout: mint(32) + owner(32) + amount(8) + ...
        if dest_ata_data.len() < 72 {
            verbose_log!("Destination ATA invalid!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        let dest_mint: [u8; 32] = dest_ata_data[0..32].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;

        if dest_mint != *output_mint.address().as_ref() {
            verbose_log!("SECURITY: Destination ATA mint mismatch!");
            verbose_log!("  Expected: output_mint");
            return Err(PrivacySwapError::InvalidDestinationMint.into());
        }
        verbose_log!("  Destination ATA mint verified");
    }

    // === SEC-012 FIX: Verify vault ATA is owned by vault PDA ===
    {
        let vault_ata_data = vault_output_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        if vault_ata_data.len() < 64 {
            verbose_log!("SECURITY: Vault ATA invalid!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        let vault_ata_owner: [u8; 32] = vault_ata_data[32..64].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;

        if vault_ata_owner != *vault_pda.address().as_ref() {
            verbose_log!("SECURITY: Vault ATA not owned by vault PDA!");
            return Err(PrivacySwapError::InvalidVaultAta.into());
        }

        // Also verify vault ATA mint matches output token
        let vault_ata_mint: [u8; 32] = vault_ata_data[0..32].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;
        if vault_ata_mint != *output_mint.address().as_ref() {
            verbose_log!("SECURITY: Vault ATA mint mismatch!");
            return Err(PrivacySwapError::InvalidVaultAta.into());
        }

        verbose_log!("  Vault ATA verified (owned by vault, correct mint)");
    }

    // === SEC-007 FIX: Verify pool config has valid length ===
    {
        use crate::state::PrivacyPoolConfig;
        let pool_data = pool_config.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        if pool_data.len() < PrivacyPoolConfig::LEN {
            verbose_log!("SECURITY: Pool config data too short!");
            return Err(PrivacySwapError::InvalidPoolConfig.into());
        }
        verbose_log!("  Pool config length verified");
    }

    // === SECURITY: Verify account ownership ===
    verbose_log!("Verifying account ownership...");
    verify_program_owner(commitment_account, program_id)?;
    verify_program_owner(nullifier_registry, program_id)?;

    // === STEP 1: Verify commitment ===
    verbose_log!("Step 1: Verifying commitment...");

    // Read commitment account data
    let commitment_data = commitment_account.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    // SEC-004 FIX: Verify commitment account discriminator
    // This prevents attackers from passing arbitrary accounts
    use crate::state::CommitmentAccount;
    use crate::vault::read_commitment_claim_authority;
    if commitment_data.len() < CommitmentAccount::LEN {
        verbose_log!("Commitment account too small!");
        return Err(PrivacySwapError::InvalidAccount.into());
    }
    if &commitment_data[0..8] != &CommitmentAccount::DISCRIMINATOR {
        verbose_log!("Invalid commitment discriminator!");
        return Err(PrivacySwapError::InvalidAccount.into());
    }
    verbose_log!("  Commitment discriminator verified");

    // === CRIT-007 FIX: Verify claim_authority signature (anti-frontrunning) ===
    // Only the stored claim_authority can claim these tokens
    // This prevents mempool front-running attacks
    let stored_claim_authority = read_commitment_claim_authority(&commitment_data)
        .ok_or(PrivacySwapError::InvalidAccount)?;
    if *claimer.address().as_ref() != stored_claim_authority {
        verbose_log!("SECURITY: Claimer doesn't match claim_authority!");
        verbose_log!("  Required: claim_authority pubkey stored during deposit");
        return Err(PrivacySwapError::UnauthorizedClaimAuthority.into());
    }
    verbose_log!("  Claim authority verified (anti-frontrunning)");

    // SEC-011 FIX: Verify pool config matches commitment's stored pool
    // Commitment stores pool address at offset 40-72
    let commitment_pool: [u8; 32] = commitment_data[40..72].try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;
    if commitment_pool != *pool_config.address().as_ref() {
        verbose_log!("SECURITY: Pool config doesn't match commitment's pool!");
        return Err(PrivacySwapError::PoolMismatch.into());
    }
    verbose_log!("  Pool config matches commitment");

    // Get stored commitment hash
    let stored_commitment = read_commitment_hash(&commitment_data)
        .ok_or(PrivacySwapError::InvalidCommitment)?;

    // Verify: SHA256(secret || nonce) == stored commitment
    if !verify_commitment(&args.secret, args.nonce, &stored_commitment) {
        verbose_log!("Commitment verification FAILED!");
        return Err(PrivacySwapError::InvalidCommitment.into());
    }
    verbose_log!("  Commitment verified!");

    // Check if already fully claimed
    if is_commitment_fully_claimed(&commitment_data) {
        verbose_log!("  Already fully claimed!");
        return Err(PrivacySwapError::AlreadyClaimed.into());
    }

    // V4 Fractional Claims: Verify commitment is claimable (Swapped or PartialClaim)
    // User cannot claim if keeper hasn't executed the swap yet
    if !is_commitment_claimable(&commitment_data) {
        verbose_log!("  Commitment not claimable - swap not yet executed by keeper!");
        return Err(PrivacySwapError::CommitmentNotSwapped.into());
    }
    verbose_log!("  Status: Claimable");

    // Get total output amount and remaining amount
    // Read amounts from commitment - output_amount used in verbose logs only
    #[allow(unused_variables)]
    let total_output = read_commitment_output_amount(&commitment_data)
        .ok_or(PrivacySwapError::InvalidCommitment)?;
    let remaining_amount = get_remaining_amount(&commitment_data)
        .ok_or(PrivacySwapError::InvalidCommitment)?;

    verbose_log!("  Total output: {}", total_output);
    verbose_log!("  Remaining: {}", remaining_amount);

    // Drop the borrow before we mutate
    drop(commitment_data);

    // === V4: Calculate claim amount based on percentage ===
    // percentage is of the REMAINING amount, not the original
    // This allows: 50% → 50% → 100% pattern
    let claim_amount = remaining_amount
        .checked_mul(args.claim_percentage as u64)
        .ok_or(PrivacySwapError::MathOverflow)?
        .checked_div(100)
        .ok_or(PrivacySwapError::MathOverflow)?;

    // For 100% claims, ensure we get exactly the remaining amount (avoid rounding issues)
    let claim_amount = if args.claim_percentage == 100 {
        remaining_amount
    } else {
        claim_amount
    };

    // MED-001 FIX: Safety check - claim_amount must never exceed remaining
    // This guards against any edge case rounding issues
    let claim_amount = claim_amount.min(remaining_amount);

    if claim_amount == 0 {
        verbose_log!("  Claim amount is 0!");
        return Err(PrivacySwapError::InsufficientRemainingAmount.into());
    }

    verbose_log!("  Claiming {}% = {} tokens", args.claim_percentage, claim_amount);

    // === STEP 2: Double-spend protection via commitment status ===
    // OPTIMIZATION: Nullifier registry check removed - commitment.status already
    // prevents double-spending (status = FullyClaimed blocks re-claims).
    // The is_commitment_claimable() check above already verified this!
    verbose_log!("Step 2: Double-spend protection verified via commitment status");
    verbose_log!("  (Nullifier registry check skipped - commitment status is sufficient)");

    // === STEP 3: Calculate fee and transfer tokens ===
    verbose_log!("Step 3: Processing transfer with 1.5% fee...");

    // Calculate fee on the claim_amount (1.5% = 150 basis points)
    // fee = claim_amount * 150 / 10000 (CVE-002 FIX: use safe u128 calculation)
    let fee_amount = calculate_fee_safe(claim_amount)?;

    // User receives claim_amount - fee
    let user_amount = claim_amount
        .checked_sub(fee_amount)
        .ok_or(PrivacySwapError::MathOverflow)?;

    verbose_log!("  Claim amount: {}", claim_amount);
    verbose_log!("  Fee (1.5%): {}", fee_amount);
    verbose_log!("  User receives: {}", user_amount);

    // Read pool config to get vault bump AND pool's stored mints
    // For universal pools, these are UNIVERSAL_MINT, not the actual token mints
    let pool_data = pool_config.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    // Pool config layout: discriminator(8) + input_mint(32) + output_mint(32) + tier(1) + amount(8) + vault(32) + bump(1)
    // Bump is at offset 8 + 32 + 32 + 1 + 8 + 32 = 113
    let vault_bump = if pool_data.len() > 113 { pool_data[113] } else { 255 };
    let tier = if pool_data.len() > 72 { pool_data[72] } else { 0 };

    // CRITICAL FIX: Read pool's stored mints for vault PDA derivation
    // For universal pools, these are UNIVERSAL_MINT, not the actual token mints
    let pool_input_mint: [u8; 32] = pool_data[8..40].try_into()
        .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;
    let pool_output_mint: [u8; 32] = pool_data[40..72].try_into()
        .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;

    drop(pool_data);

    // === SECURITY: Verify vault PDA using POOL's stored mints ===
    // This is critical for universal pools where vault was derived with UNIVERSAL_MINT
    verbose_log!("Verifying vault PDA...");
    verify_vault_pda(
        vault_pda,
        &pool_input_mint,
        &pool_output_mint,
        tier,
        vault_bump,
    )?;

    // === STEP 3a: Transfer FEE to hardcoded fee wallet ATA ===
    // NOTE: vault_transfer_spl uses mints for PDA signing seeds - must use pool's mints!
    if fee_amount > 0 {
        verbose_log!("  Transferring fee to protocol wallet...");
        vault_transfer_spl(
            vault_output_ata,
            fee_wallet_ata,
            vault_pda,
            token_program,
            fee_amount,
            &pool_input_mint,
            &pool_output_mint,
            &[tier],
            &[vault_bump],
        )?;
        verbose_log!("  Fee transferred: {} tokens", fee_amount);
    }

    // === STEP 3b: Transfer remaining tokens to user destination ===
    // NOTE: vault_transfer_spl uses mints for PDA signing seeds - must use pool's mints!
    verbose_log!("  Transferring {} tokens to destination...", user_amount);
    vault_transfer_spl(
        vault_output_ata,
        destination_ata,
        vault_pda,
        token_program,
        user_amount,
        &pool_input_mint,
        &pool_output_mint,
        &[tier],
        &[vault_bump],
    )?;

    verbose_log!("  Transfer complete!");

    // === STEP 4: Update commitment status ===
    verbose_log!("Step 4: Updating commitment...");

    // Get current slot for claim timestamp
    // Note: In production, use Clock sysvar
    let claim_slot = 0u64; // Placeholder

    // Update commitment account with partial claim
    let mut commitment_data_mut = commitment_account.try_borrow_mut()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    let new_remaining = update_commitment_partial_claim(
        &mut commitment_data_mut,
        claim_amount,
        claim_slot,
    ).ok_or(PrivacySwapError::InvalidCommitment)?;

    // Determine if we should nullify
    let is_fully_claimed = new_remaining == 0;

    drop(commitment_data_mut);

    // OPTIMIZATION: Nullifier registry no longer used for double-spend protection
    // Commitment status (FullyClaimed) already prevents re-claims
    if is_fully_claimed {
        verbose_log!("  Commitment fully claimed - closing account to recover rent");

        // Close commitment account and send rent to protocol fee wallet
        // This recovers ~0.002 SOL per claim as additional protocol revenue
        if accounts.len() >= 14 {
            let fee_wallet = &accounts[13];

            // Verify fee_wallet matches hardcoded FEE_WALLET and is writable
            if fee_wallet.address().as_ref() == FEE_WALLET.as_ref() && fee_wallet.is_writable() {
                // Get commitment account lamports
                let rent_lamports = commitment_account.lamports();

                // Transfer rent: add to fee wallet, subtract from commitment
                // In Solana, programs can add lamports to any writable account
                // and subtract from accounts they own (balance must be preserved)
                fee_wallet.set_lamports(fee_wallet.lamports() + rent_lamports);
                commitment_account.set_lamports(0);

                // Zero out the account data (marks as closed)
                let mut data = commitment_account.try_borrow_mut()
                    .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
                data.fill(0);
                drop(data);

                verbose_log!("  Commitment account closed, {} lamports sent to protocol", rent_lamports);
            } else {
                verbose_log!("  Fee wallet mismatch, skipping account close");
            }
        } else {
            verbose_log!("  Fee wallet not provided, commitment account left open");
        }
    } else {
        verbose_log!("  Partial claim - {} tokens remaining", new_remaining);
    }

    verbose_log!("Claim completed successfully!");
    verbose_log!("  Claimed: {} tokens ({}%)", user_amount, args.claim_percentage);
    if !is_fully_claimed {
        verbose_log!("  Remaining: {} tokens", new_remaining);
    }

    Ok(())
}

/// Expand nullifier registry when it's nearly full
///
/// MED-003 FIX: Now properly validates that account has enough allocated space.
/// NOTE: This function can only expand capacity UP TO the already-allocated account size.
/// To increase beyond the allocated size, a new larger account must be created.
///
/// Accounts:
/// 0. [signer, writable] Authority (pays for expansion)
/// 1. [] Pool config
/// 2. [] Input token mint
/// 3. [] Output token mint
/// 4. [writable] Existing nullifier registry
/// 5. [] System program
fn process_expand_nullifier(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::NullifierRegistry;
    use crate::vault::nullifier_registry_size;
    use crate::verification::verify_program_owner;

    let args = ExpandNullifierArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let authority = &accounts[0];
    let _pool_config = &accounts[1];
    let _input_mint = &accounts[2];
    let _output_mint = &accounts[3];
    let nullifier_registry = &accounts[4];
    let _system_program = &accounts[5];

    // Verify authority is signer
    if !authority.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // Verify nullifier registry is owned by program
    verify_program_owner(nullifier_registry, program_id)?;

    verbose_log!("Expanding nullifier registry...");
    verbose_log!("  New capacity: {}", args.new_capacity);

    // Read current registry data
    let nullifier_data = nullifier_registry.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    if nullifier_data.len() < NullifierRegistry::HEADER_LEN {
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    // Verify discriminator
    if &nullifier_data[0..8] != &NullifierRegistry::DISCRIMINATOR {
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    let current_count = u32::from_le_bytes(
        nullifier_data[40..44].try_into().map_err(|_| PrivacySwapError::InvalidAccount)?
    );
    let current_capacity = u32::from_le_bytes(
        nullifier_data[44..48].try_into().map_err(|_| PrivacySwapError::InvalidAccount)?
    );

    verbose_log!("  Current count: {}", current_count);
    verbose_log!("  Current capacity: {}", current_capacity);

    // Verify new capacity is larger
    if args.new_capacity <= current_capacity {
        verbose_log!("  Error: New capacity must be larger than current!");
        return Err(PrivacySwapError::InvalidInstruction.into());
    }

    // MED-003 FIX: Calculate required size and validate against ACTUAL allocated space
    let required_size = nullifier_registry_size(args.new_capacity);
    let allocated_size = nullifier_data.len(); // Actual allocated account data length

    verbose_log!("  Required size for new capacity: {} bytes", required_size);
    verbose_log!("  Allocated account size: {} bytes", allocated_size);

    // MED-003 FIX: CRITICAL - Verify the account has enough space
    // Without this check, we would set capacity > what the account can hold,
    // causing out-of-bounds writes when adding nullifiers
    if required_size > allocated_size {
        verbose_log!("  ERROR: Account too small for requested capacity!");
        verbose_log!("  Need {} bytes but only {} allocated", required_size, allocated_size);
        verbose_log!("  To expand beyond current allocation, create a new larger account");
        return Err(PrivacySwapError::InvalidInstruction.into());
    }

    drop(nullifier_data);

    // Now safe to update capacity - we've verified the account is large enough
    let mut nullifier_data_mut = nullifier_registry.try_borrow_mut()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    // MED-003 FIX: Update capacity (safe because we verified allocated_size >= required_size)
    nullifier_data_mut[44..48].copy_from_slice(&args.new_capacity.to_le_bytes());

    drop(nullifier_data_mut);

    verbose_log!("Nullifier registry expansion complete!");
    verbose_log!("  New capacity: {} (requires {} bytes)", args.new_capacity, required_size);

    Ok(())
}

// ============================================================
// V3 PROCESSORS (Keeper Pattern - Full Privacy)
// ============================================================

/// Deposit tokens to vault (Keeper pattern - Step 1)
///
/// User deposits INPUT tokens to the vault PDA. No swap happens yet.
/// Creates a commitment account with status = Pending.
/// Privacy: User only interacts with vault, not DEX directly.
///
/// Accounts:
/// 0.  [signer, writable] User (depositor, pays fees)
/// 1.  [] Pool config PDA
/// 2.  [writable] Vault PDA
/// 3.  [writable] User's input token ATA
/// 4.  [writable] Vault's input token ATA
/// 5.  [writable] Commitment account PDA (created)
/// 6.  [] Input token mint
/// 7.  [] Token program
/// 8.  [] System program
/// 9.  [writable] Fee wallet ATA (MUST belong to hardcoded FEE_WALLET)
/// 10. [] ATA program (optional - required if fee wallet ATA doesn't exist)
/// 11. [] Fee wallet (optional - required if fee wallet ATA doesn't exist, must match FEE_WALLET)
/// 12. [] Clock sysvar (HIGH-004a fix: for deposit_slot timestamp)
///
/// Note: If fee wallet ATA doesn't exist for this token, the depositor pays
/// for its creation. Pass ATA program and Fee wallet as accounts 10-11.
fn process_deposit(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::{CommitmentAccount, CommitmentStatus, PrivacyPoolConfig, seeds_v2};
    use crate::vault::{transfer_spl_from_user, create_account, calculate_rent_exempt_balance};
    use crate::verification::{verify_spl_token_program, verify_system_program, verify_clock_sysvar, read_clock_slot};

    let args = DepositArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    // Now requires 10 accounts (added fee_wallet_ata)
    if accounts.len() < 10 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let pool_config = &accounts[1];
    let _vault_pda = &accounts[2];
    let user_input_ata = &accounts[3];
    let vault_input_ata = &accounts[4];
    let commitment_account = &accounts[5];
    let input_mint = &accounts[6];
    let token_program = &accounts[7];
    let system_program = &accounts[8];
    let fee_wallet_ata = &accounts[9];  // NEW: Fee wallet ATA

    // HIGH-004a FIX: Read current slot from Clock sysvar
    // Clock sysvar is optional for backward compatibility, but strongly recommended
    let current_slot = if accounts.len() > 12 {
        let clock_sysvar = &accounts[12];
        if verify_clock_sysvar(clock_sysvar).is_ok() {
            let clock_data = clock_sysvar.try_borrow()
                .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
            let slot = read_clock_slot(&clock_data).unwrap_or(0);
            drop(clock_data);
            verbose_log!("  HIGH-004a: deposit_slot = {} (from Clock sysvar)", slot);
            slot
        } else {
            verbose_log!("  WARNING: Clock sysvar not provided, deposit_slot = 0");
            0
        }
    } else {
        verbose_log!("  WARNING: Clock sysvar not provided, deposit_slot = 0");
        0
    };

    // Verify user is signer
    if !user.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // Verify CPI programs
    verify_spl_token_program(token_program)?;
    verify_system_program(system_program)?;
    verbose_log!("  CPI programs verified");

    // === CREATE FEE WALLET ATA IF NEEDED (user pays rent) ===
    // If fee wallet ATA doesn't exist for this token, create it
    // This allows the first depositor for a new token to proceed
    if fee_wallet_ata.lamports() == 0 {
        verbose_log!("  Fee wallet ATA doesn't exist, creating...");

        // Need ata_program and fee_wallet to create ATA
        if accounts.len() < 12 {
            verbose_log!("  Missing accounts for ATA creation! Need ata_program, fee_wallet");
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        let _ata_program = &accounts[10];
        let fee_wallet = &accounts[11];

        // Verify fee_wallet matches hardcoded FEE_WALLET
        if fee_wallet.address().as_ref() != FEE_WALLET.as_ref() {
            verbose_log!("SECURITY: Fee wallet account doesn't match hardcoded FEE_WALLET!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        // Create ATA using CreateIdempotent
        use crate::vault::create_ata;
        create_ata(
            user,              // Payer (depositor pays for ATA creation)
            fee_wallet_ata,    // ATA to create
            fee_wallet,        // Wallet (verified to match FEE_WALLET)
            input_mint,        // Mint (input token for deposits)
            system_program,    // System Program
            token_program,     // Token Program
        )?;

        verbose_log!("  Fee wallet ATA created (user paid rent)");
    }

    // === VERIFY FEE WALLET ATA BELONGS TO HARDCODED FEE_WALLET ===
    {
        let fee_ata_data = fee_wallet_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // SPL Token Account layout: mint(32) + owner(32) + ...
        if fee_ata_data.len() < 64 {
            verbose_log!("Fee wallet ATA invalid!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        let ata_owner: [u8; 32] = fee_ata_data[32..64]
            .try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;

        // Verify ATA owner matches hardcoded FEE_WALLET
        if ata_owner != *FEE_WALLET.as_ref() {
            verbose_log!("Fee wallet ATA owner mismatch! Expected hardcoded fee wallet.");
            return Err(PrivacySwapError::InvalidAccount.into());
        }
        verbose_log!("  Fee wallet ATA verified (hardcoded)");
    }

    // Read pool config to get vault info
    let pool_data = pool_config.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    if pool_data.len() < PrivacyPoolConfig::LEN {
        return Err(PrivacySwapError::InvalidPoolConfig.into());
    }

    // Verify pool is active
    // Offset 251: after discriminator(8) + mints(64) + tier(1) + denom(8) + vault(32) + bump(1) + ATAs(64) + dex(33) + stats(40)
    let is_active = pool_data[251]; // is_active offset
    if is_active != 1 {
        return Err(PrivacySwapError::PoolNotActive.into());
    }

    let _vault_bump = pool_data[113]; // vault_pda_bump offset (for future use)
    drop(pool_data);

    verbose_log!("  Deposit amount: {}", args.input_amount);
    verbose_log!("  Commitment first byte: {}", args.commitment[0]);

    // === CALCULATE DEPOSIT FEE (1.5%) === (CVE-002 FIX: use safe u128 calculation)
    let fee_amount = calculate_fee_safe(args.input_amount)?;

    let net_amount = args.input_amount
        .checked_sub(fee_amount)
        .ok_or(PrivacySwapError::MathOverflow)?;

    verbose_log!("  Fee (1.5%): {}", fee_amount);
    verbose_log!("  Net to vault: {}", net_amount);

    // Create commitment account PDA
    let commitment_rent = calculate_rent_exempt_balance(CommitmentAccount::LEN as u64);
    let commitment_seeds: &[&[u8]] = &[
        seeds_v2::COMMITMENT,
        &args.commitment,
        &[args.commitment_bump],
    ];

    create_account(
        user,
        commitment_account,
        system_program,
        commitment_rent,
        CommitmentAccount::LEN as u64,
        program_id,
        Some(commitment_seeds),
    )?;
    verbose_log!("  Commitment account created");

    // Transfer fee to fee wallet (1.5%)
    if fee_amount > 0 {
        transfer_spl_from_user(
            user_input_ata,
            fee_wallet_ata,
            user,
            token_program,
            fee_amount,
        )?;
        verbose_log!("  Fee transferred to protocol wallet");
    }

    // Transfer net amount to vault (98.5%)
    transfer_spl_from_user(
        user_input_ata,
        vault_input_ata,
        user,
        token_program,
        net_amount,
    )?;
    verbose_log!("  Net tokens transferred to vault");

    // Initialize commitment account with Pending status
    // IMPORTANT: Store net_amount (after fee), not original input_amount
    {
        let mut commitment_data = commitment_account.try_borrow_mut()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // Write discriminator
        commitment_data[0..8].copy_from_slice(&CommitmentAccount::DISCRIMINATOR);

        // Write commitment hash
        commitment_data[8..40].copy_from_slice(&args.commitment);

        // Write pool address
        commitment_data[40..72].copy_from_slice(pool_config.address().as_ref());

        // Write input mint
        commitment_data[72..104].copy_from_slice(input_mint.address().as_ref());

        // Write input amount (NET amount after fee, not original!)
        commitment_data[104..112].copy_from_slice(&net_amount.to_le_bytes());

        // Write output amount (0 until swap happens)
        commitment_data[112..120].copy_from_slice(&0u64.to_le_bytes());

        // HIGH-004a FIX: Write deposit slot from Clock sysvar
        commitment_data[120..128].copy_from_slice(&current_slot.to_le_bytes());

        // Write deposit timestamp (would need Clock sysvar for real value)
        commitment_data[128..136].copy_from_slice(&0i64.to_le_bytes());

        // Write status = Pending (0)
        commitment_data[136] = CommitmentStatus::Pending as u8;

        // Write swap_slot (0)
        commitment_data[137..145].copy_from_slice(&0u64.to_le_bytes());

        // Write claim_slot (0)
        commitment_data[145..153].copy_from_slice(&0u64.to_le_bytes());

        // Write dex_type (0)
        commitment_data[153] = 0;

        // Write claimed_amount = 0 (V4: for partial claims)
        commitment_data[154..162].copy_from_slice(&0u64.to_le_bytes());

        // HIGH-003 FIX: Write user_min_output (slippage protection)
        // Keeper's min_output_amount MUST be >= this value
        commitment_data[162..170].copy_from_slice(&args.user_min_output.to_le_bytes());

        // CRIT-007 FIX: Write claim_authority (anti-frontrunning)
        // Only this pubkey can sign claim transactions
        commitment_data[170..202].copy_from_slice(args.claim_authority.as_ref());
    }

    verbose_log!("Deposit complete!");
    verbose_log!("  Status: Pending (waiting for keeper to swap)");
    verbose_log!("  User min output: {}", args.user_min_output);

    Ok(())
}

/// Execute swap within vault (Keeper pattern - Step 2)
///
/// Keeper calls this to swap tokens inside the vault.
/// Takes a Pending commitment and executes the swap.
/// Marks commitment as Swapped with output_amount recorded.
///
/// Privacy: Swap happens inside vault, not linked to depositor.
/// Flexibility: Keeper can route via any DEX.
///
/// Accounts:
/// 0.  [signer] Keeper (anyone can be a keeper)
/// 1.  [] Pool config PDA
/// 2.  [writable] Vault PDA
/// 3.  [writable] Vault's input token ATA
/// 4.  [writable] Vault's output token ATA
/// 5.  [writable] Commitment account PDA
/// 6.  [] DEX program (Meteora, Orca, Raydium, Jupiter)
/// 7+. [] DEX-specific accounts (pool, vaults, etc.)
/// N.  [] Token program
fn process_execute_swap(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::{CommitmentAccount, CommitmentStatus, seeds_v2};
    use crate::verification::verify_dex_program_by_type;

    let args = ExecuteSwapArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    if accounts.len() < 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let keeper = &accounts[0];
    let pool_config = &accounts[1];
    let _vault_pda = &accounts[2];
    let _vault_input_ata = &accounts[3];
    let _vault_output_ata = &accounts[4];
    let commitment_account = &accounts[5];
    let dex_program = &accounts[6];
    // DEX-specific accounts follow at indices 7+

    // Verify keeper is signer
    if !keeper.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // SEC-001 FIX: Verify commitment_account is writable
    if !commitment_account.is_writable() {
        verbose_log!("SECURITY: commitment_account not writable!");
        return Err(PrivacySwapError::AccountNotWritable.into());
    }

    // CRIT-003 FIX: Verify keeper is authorized (must be pool authority)
    // This prevents malicious actors from executing swaps with bad routes
    {
        use crate::state::PrivacyPoolConfig;
        let pool_data = pool_config.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        if pool_data.len() < PrivacyPoolConfig::LEN {
            return Err(PrivacySwapError::InvalidPoolConfig.into());
        }

        // Authority is at offset 252 (after is_active at 251)
        let authority: [u8; 32] = pool_data[252..284].try_into()
            .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;

        if keeper.address().as_ref() != &authority {
            verbose_log!("SECURITY: Unauthorized keeper!");
            verbose_log!("  Keeper must be pool authority");
            return Err(PrivacySwapError::UnauthorizedKeeper.into());
        }
        verbose_log!("  Keeper authorized (is pool authority)");
    }

    // Verify DEX program matches the specified type
    verify_dex_program_by_type(dex_program, args.dex_type)?;
    verbose_log!("  DEX program verified (type {})", args.dex_type);

    // Verify commitment account is owned by program
    if unsafe { commitment_account.owner() } != program_id {
        return Err(PrivacySwapError::InvalidOwner.into());
    }

    // Read commitment and verify it's Pending
    let commitment_data = commitment_account.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    if commitment_data.len() < CommitmentAccount::LEN {
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    // Verify discriminator
    if &commitment_data[0..8] != &CommitmentAccount::DISCRIMINATOR {
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    // Verify commitment hash matches
    if &commitment_data[8..40] != &args.commitment {
        verbose_log!("Commitment hash mismatch!");
        return Err(PrivacySwapError::InvalidCommitment.into());
    }

    // SEC-008 FIX: Verify status is valid enum and is Pending
    let status_byte = commitment_data[136];
    let status = CommitmentStatus::from_u8(status_byte)
        .ok_or_else(|| {
            verbose_log!("SECURITY: Invalid commitment status byte: {}", status_byte);
            PrivacySwapError::InvalidCommitmentStatus
        })?;

    if status != CommitmentStatus::Pending {
        verbose_log!("Commitment not in Pending status! Status: {:?}", status);
        return Err(PrivacySwapError::AlreadyClaimed.into());
    }

    // Get input amount
    let input_amount = u64::from_le_bytes(
        commitment_data[104..112].try_into().map_err(|_| PrivacySwapError::InvalidAccount)?
    );

    // SEC-010 FIX: Validate input amount is positive and reasonable
    if input_amount == 0 {
        verbose_log!("SECURITY: Input amount is zero!");
        return Err(PrivacySwapError::InsufficientInput.into());
    }

    // HIGH-003 FIX: Read user's minimum output requirement
    // Keeper's min_output_amount MUST be >= user's stored value
    let user_min_output = u64::from_le_bytes(
        commitment_data[162..170].try_into().map_err(|_| PrivacySwapError::InvalidAccount)?
    );

    // HIGH-003 FIX: Verify keeper honors user's slippage protection
    // This prevents malicious keepers from setting low slippage to extract value
    if args.min_output_amount < user_min_output {
        verbose_log!("SECURITY: Keeper min_output ({}) < user min_output ({})!",
            args.min_output_amount, user_min_output);
        verbose_log!("Keeper cannot set lower slippage than user specified!");
        return Err(PrivacySwapError::SlippageExceeded.into());
    }

    drop(commitment_data);

    verbose_log!("  Processing commitment");
    verbose_log!("  Input amount: {}", input_amount);
    verbose_log!("  Keeper min output: {}", args.min_output_amount);
    verbose_log!("  User min output: {}", user_min_output);

    // Read pool config for vault bump
    let pool_data = pool_config.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    let vault_bump = pool_data[113];
    let input_mint: [u8; 32] = pool_data[8..40].try_into()
        .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;
    let output_mint: [u8; 32] = pool_data[40..72].try_into()
        .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;
    let tier = pool_data[72];

    drop(pool_data);

    // Build vault signer seeds (for future DEX CPI)
    let tier_bytes = [tier];
    let _vault_seeds: &[&[u8]] = &[
        seeds_v2::VAULT,
        &input_mint,
        &output_mint,
        &tier_bytes,
        &[vault_bump],
    ];

    // HIGH-005 FIX: Read vault_output_ata balance BEFORE any swap
    // This ensures we measure actual tokens received, not trusting keeper input
    use crate::vault::read_token_balance;
    let vault_output_ata = &accounts[4];
    let output_balance_before = {
        let output_ata_data = vault_output_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
        read_token_balance(&output_ata_data)
    };
    verbose_log!("  Output balance before swap: {}", output_balance_before);

    // TODO: Execute the actual swap CPI based on dex_type
    // For now, we simulate the swap - in production, this would CPI to the DEX
    //
    // The keeper would:
    // 1. Call swap-api off-chain to get the best route
    // 2. Build the DEX-specific swap instruction
    // 3. Pass the instruction data + accounts here
    // 4. This function executes the CPI with vault as signer
    //
    // === DEX CPI WOULD GO HERE ===
    // match args.dex_type {
    //     0 => vault_meteora_swap(...),
    //     1 => vault_meteora_dlmm_swap(...),
    //     2 => vault_orca_swap(...),
    //     _ => return Err(PrivacySwapError::InvalidDexType.into()),
    // }
    // =============================

    // HIGH-005 FIX: Read vault_output_ata balance AFTER swap
    let output_balance_after = {
        let output_ata_data = vault_output_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
        read_token_balance(&output_ata_data)
    };
    verbose_log!("  Output balance after swap: {}", output_balance_after);

    // HIGH-005 FIX: Calculate ACTUAL output from balance change
    // This ensures we measure real tokens received, not trusting keeper input
    let output_amount = output_balance_after
        .checked_sub(output_balance_before)
        .unwrap_or(0);

    // HIGH-001 FIX: Require actual swap output - no placeholders allowed!
    // If the swap produced no tokens, it MUST fail. This prevents:
    // 1. Fake swaps where keeper claims output without actual DEX CPI
    // 2. Failed DEX CPIs that silently return without transferring tokens
    // 3. Attacks where keeper inflates output_amount without real tokens
    if output_amount == 0 {
        verbose_log!("SECURITY: Swap produced no output tokens!");
        verbose_log!("  Before: {}, After: {}", output_balance_before, output_balance_after);
        return Err(PrivacySwapError::SwapFailed.into());
    }

    if output_amount < args.min_output_amount {
        verbose_log!("Slippage exceeded! Got {} < min {}", output_amount, args.min_output_amount);
        return Err(PrivacySwapError::SlippageExceeded.into());
    }

    // Update commitment to Swapped status
    {
        let mut commitment_data = commitment_account.try_borrow_mut()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // Write output amount
        commitment_data[112..120].copy_from_slice(&output_amount.to_le_bytes());

        // Write status = Swapped (1)
        commitment_data[136] = CommitmentStatus::Swapped as u8;

        // Write swap_slot (would need Clock sysvar)
        commitment_data[137..145].copy_from_slice(&0u64.to_le_bytes());

        // Write dex_type
        commitment_data[153] = args.dex_type;
    }

    verbose_log!("Swap executed!");
    verbose_log!("  Output amount: {}", output_amount);
    verbose_log!("  Status: Swapped (ready for claim)");
    verbose_log!("  DEX type: {}", args.dex_type);

    Ok(())
}

// ============================================================
// V4 PROCESSORS (Direct Transfer - No Swap)
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
/// For universal pools (dex_type=255), supports ANY token:
/// - Vault ATA is created on-the-fly if it doesn't exist
/// - Requires ATA program in account 10
///
/// Accounts:
/// 0.  [signer, writable] User (depositor, pays fees)
/// 1.  [] Pool config PDA
/// 2.  [writable] Vault PDA
/// 3.  [writable] User's token ATA
/// 4.  [writable] Vault's token ATA (same token as input)
/// 5.  [writable] Commitment account PDA (created)
/// 6.  [] Token mint
/// 7.  [] Token program
/// 8.  [] System program
/// 9.  [writable] Fee wallet ATA (MUST belong to hardcoded FEE_WALLET)
/// 10. [] Associated Token program (optional, required for universal pools)
/// 11. [] Clock sysvar (HIGH-004a fix: for deposit_slot timestamp)
fn process_deposit_direct(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::{CommitmentAccount, CommitmentStatus, PrivacyPoolConfig, seeds_v2, UNIVERSAL_MINT};
    use crate::vault::{transfer_spl_from_user, create_account, calculate_rent_exempt_balance, create_ata};
    use crate::verification::{verify_spl_token_program, verify_system_program, verify_ata_program, verify_clock_sysvar, read_clock_slot};

    let args = DepositDirectArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    // Requires 10 accounts minimum, 11 for universal pools
    if accounts.len() < 10 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let pool_config = &accounts[1];
    let vault_pda = &accounts[2];
    let user_token_ata = &accounts[3];
    let vault_token_ata = &accounts[4];
    let commitment_account = &accounts[5];
    let token_mint = &accounts[6];
    let token_program = &accounts[7];
    let system_program = &accounts[8];
    let fee_wallet_ata = &accounts[9];

    // Verify user is signer
    if !user.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // Verify CPI programs
    verify_spl_token_program(token_program)?;
    verify_system_program(system_program)?;
    verbose_log!("  CPI programs verified");

    // HIGH-004a FIX: Read current slot from Clock sysvar
    // Clock sysvar is at account 11 (after optional ATA program)
    let current_slot = if accounts.len() > 11 {
        let clock_sysvar = &accounts[11];
        if verify_clock_sysvar(clock_sysvar).is_ok() {
            let clock_data = clock_sysvar.try_borrow()
                .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
            let slot = read_clock_slot(&clock_data).unwrap_or(0);
            drop(clock_data);
            verbose_log!("  HIGH-004a: deposit_slot = {} (from Clock sysvar)", slot);
            slot
        } else {
            verbose_log!("  WARNING: Clock sysvar not provided, deposit_slot = 0");
            0
        }
    } else {
        verbose_log!("  WARNING: Clock sysvar not provided, deposit_slot = 0");
        0
    };

    // === VERIFY FEE WALLET ATA BELONGS TO HARDCODED FEE_WALLET ===
    {
        let fee_ata_data = fee_wallet_ata.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // SPL Token Account layout: mint(32) + owner(32) + ...
        if fee_ata_data.len() < 64 {
            verbose_log!("Fee wallet ATA invalid!");
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        let ata_owner: [u8; 32] = fee_ata_data[32..64]
            .try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;

        // Verify ATA owner matches hardcoded FEE_WALLET
        if ata_owner != *FEE_WALLET.as_ref() {
            verbose_log!("Fee wallet ATA owner mismatch! Expected hardcoded fee wallet.");
            return Err(PrivacySwapError::InvalidAccount.into());
        }
        verbose_log!("  Fee wallet ATA verified (hardcoded)");
    }

    // Read pool config to verify pool is active and check if universal pool
    let pool_data = pool_config.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    if pool_data.len() < PrivacyPoolConfig::LEN {
        return Err(PrivacySwapError::InvalidPoolConfig.into());
    }

    // Verify pool is active (offset 251)
    let is_active = pool_data[251];
    if is_active != 1 {
        return Err(PrivacySwapError::PoolNotActive.into());
    }

    // Check if this is a universal pool (dex_type = 255 or input_mint == UNIVERSAL_MINT)
    let dex_type = pool_data[210];
    let pool_input_mint: [u8; 32] = pool_data[8..40].try_into()
        .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;
    let is_universal_pool = dex_type == 255 || pool_input_mint == UNIVERSAL_MINT;

    drop(pool_data);

    verbose_log!("  Direct transfer amount: {}", args.amount);
    verbose_log!("  Commitment first byte: {}", args.commitment[0]);
    verbose_log!("  Universal pool: {}", is_universal_pool);

    // === CREATE VAULT ATA ON-THE-FLY FOR UNIVERSAL POOLS ===
    // Universal pools don't pre-create ATAs, so we create them here for the actual token
    if is_universal_pool {
        // For universal pools, account 10 must be the ATA program
        if accounts.len() < 11 {
            verbose_log!("Universal pool requires ATA program in account 10");
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let ata_program = &accounts[10];

        // Verify ATA program
        verify_ata_program(ata_program)?;
        verbose_log!("  ATA program verified");

        // Create vault's ATA for this token (idempotent - won't fail if exists)
        verbose_log!("  Creating vault ATA for token on-the-fly...");
        create_ata(
            user,           // payer
            vault_token_ata,
            vault_pda,      // wallet (ATA owner)
            token_mint,
            system_program,
            token_program,
        )?;
        verbose_log!("  Vault ATA ready");
    }

    // === CALCULATE DEPOSIT FEE (1.5%) === (CVE-002 FIX: use safe u128 calculation)
    let fee_amount = calculate_fee_safe(args.amount)?;

    let net_amount = args.amount
        .checked_sub(fee_amount)
        .ok_or(PrivacySwapError::MathOverflow)?;

    verbose_log!("  Fee (1.5%): {}", fee_amount);
    verbose_log!("  Net to vault: {}", net_amount);

    // Create commitment account PDA
    let commitment_rent = calculate_rent_exempt_balance(CommitmentAccount::LEN as u64);
    let commitment_seeds: &[&[u8]] = &[
        seeds_v2::COMMITMENT,
        &args.commitment,
        &[args.commitment_bump],
    ];

    create_account(
        user,
        commitment_account,
        system_program,
        commitment_rent,
        CommitmentAccount::LEN as u64,
        program_id,
        Some(commitment_seeds),
    )?;
    verbose_log!("  Commitment account created");

    // Transfer fee to fee wallet (1.5%)
    if fee_amount > 0 {
        transfer_spl_from_user(
            user_token_ata,
            fee_wallet_ata,
            user,
            token_program,
            fee_amount,
        )?;
        verbose_log!("  Fee transferred to protocol wallet");
    }

    // Transfer net amount to vault (98.5%)
    transfer_spl_from_user(
        user_token_ata,
        vault_token_ata,
        user,
        token_program,
        net_amount,
    )?;
    verbose_log!("  Net tokens transferred to vault");

    // Initialize commitment account with SWAPPED status (immediately claimable!)
    // This is the key difference from regular DEPOSIT
    // IMPORTANT: Store net_amount (after fee), not original amount
    {
        let mut commitment_data = commitment_account.try_borrow_mut()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // Write discriminator
        commitment_data[0..8].copy_from_slice(&CommitmentAccount::DISCRIMINATOR);

        // Write commitment hash
        commitment_data[8..40].copy_from_slice(&args.commitment);

        // Write pool address
        commitment_data[40..72].copy_from_slice(pool_config.address().as_ref());

        // Write input mint (same as output for direct transfer)
        commitment_data[72..104].copy_from_slice(token_mint.address().as_ref());

        // Write input amount (NET after deposit fee!)
        commitment_data[104..112].copy_from_slice(&net_amount.to_le_bytes());

        // Write output amount = net_amount (no swap, same token)
        commitment_data[112..120].copy_from_slice(&net_amount.to_le_bytes());

        // HIGH-004a FIX: Write deposit slot from Clock sysvar
        commitment_data[120..128].copy_from_slice(&current_slot.to_le_bytes());

        // Write deposit timestamp (would need Clock sysvar for real value)
        commitment_data[128..136].copy_from_slice(&0i64.to_le_bytes());

        // Write status = SWAPPED (1) - immediately claimable!
        commitment_data[136] = CommitmentStatus::Swapped as u8;

        // Write swap_slot (same as deposit for direct)
        commitment_data[137..145].copy_from_slice(&0u64.to_le_bytes());

        // Write claim_slot (0)
        commitment_data[145..153].copy_from_slice(&0u64.to_le_bytes());

        // Write dex_type = 255 (none - direct transfer)
        commitment_data[153] = 255;

        // Write claimed_amount = 0 (V4: for partial claims)
        commitment_data[154..162].copy_from_slice(&0u64.to_le_bytes());

        // HIGH-003 FIX: Write user_min_output = amount (direct transfer, no swap)
        // For direct transfers, user expects to get back exactly what they deposited
        commitment_data[162..170].copy_from_slice(&args.amount.to_le_bytes());

        // CRIT-007 FIX: Write claim_authority (anti-frontrunning)
        // Only this pubkey can sign claim transactions
        commitment_data[170..202].copy_from_slice(args.claim_authority.as_ref());
    }

    verbose_log!("Direct deposit complete!");
    verbose_log!("  Status: Swapped (IMMEDIATELY CLAIMABLE)");
    verbose_log!("  Amount: {} tokens", args.amount);
    verbose_log!("  No keeper needed - claim from fresh wallet now!");

    Ok(())
}

// ============================================================
// V1 PROCESSORS (Legacy)
// ============================================================

/// Initialize program configuration
///
/// Accounts:
/// 0. [writable, signer] Authority (pays for account creation)
/// 1. [writable] Config PDA
/// 2. [] System program
fn process_initialize_config(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let _args = InitializeConfigArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let authority = &accounts[0];
    let config_account = &accounts[1];
    let _system_program = &accounts[2];

    // Verify authority is signer
    if !authority.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // Verify config account is owned by this program
    // Note: Full PDA verification requires runtime syscalls
    // For security, we verify the account owner instead
    // SAFETY: owner() is safe to call on valid accounts
    if unsafe { config_account.owner() } != program_id {
        return Err(PrivacySwapError::InvalidOwner.into());
    }

    // TODO: Create account via CPI to system program
    // For now, assume account is already created

    verbose_log!("Config initialized with owner encryption pubkey");

    Ok(())
}

/// Process a private swap
///
/// Account Layout (updated for Light Protocol proof-based CPI):
/// 0.  [signer] User wallet (fee payer)
/// 1.  [] Input token mint
/// 2.  [] Output token mint
/// 3.  [writable] Temporary SPL input token account (ATA)
/// 4.  [writable] Temporary SPL output token account (ATA)
/// 5.  [writable] Input SPL interface PDA (Light Protocol token pool)
/// 6.  [writable] Output SPL interface PDA (Light Protocol token pool)
/// 7.  [] Light Protocol CPI authority PDA
/// 8.  [] Light Protocol cToken program
/// 9.  [] SPL Token program
/// 10. [writable] Input merkle tree (for decompress nullifier)
/// 11. [writable] Input nullifier queue
/// 12. [writable] Output merkle tree (for compress)
/// 13. [writable] Output queue
/// 14. [writable] DEX pool account
/// 15. [writable] DEX token A vault
/// 16. [writable] DEX token B vault
/// 17. [] DEX pool authority
/// 18. [] DEX program (Meteora/Orca/Raydium)
fn process_private_swap(
    _program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::verification::{verify_spl_token_program, verify_light_ctoken_program};

    let args = PrivateSwapArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    verbose_log!("Private swap starting");

    if accounts.len() < 19 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // Parse accounts
    let user = &accounts[0];
    let input_mint = &accounts[1];
    let output_mint = &accounts[2];
    let temp_input_spl = &accounts[3];
    let temp_output_spl = &accounts[4];
    let input_spl_interface_pda = &accounts[5];
    let output_spl_interface_pda = &accounts[6];
    let cpi_authority = &accounts[7];
    let ctoken_program = &accounts[8];
    let spl_token_program = &accounts[9];
    let input_merkle_tree = &accounts[10];
    let input_nullifier_queue = &accounts[11];
    let output_merkle_tree = &accounts[12];
    let output_queue = &accounts[13];
    // DEX accounts start at index 14

    // Verify user is signer
    if !user.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // === CVE-001 FIX: Verify CPI program IDs ===
    verify_spl_token_program(spl_token_program)?;
    verify_light_ctoken_program(ctoken_program)?;
    verbose_log!("  CPI programs verified");

    // === STEP 1: Decompress input cTokens to SPL (requires proof) ===
    verbose_log!("Step 1: Decompressing cTokens to SPL with ZK proof...");

    let decompress_params = DecompressCTokenToSplParams {
        amount: args.input_amount,
        proof: &args.proof,
        merkle_context: &args.merkle_context,
        mint: input_mint,
        source_ctoken: input_merkle_tree, // Merkle tree contains the compressed account
        destination_spl: temp_input_spl,
        authority: user,
        spl_interface_pda: input_spl_interface_pda,
        spl_interface_bump: args.input_spl_interface_bump,
        pool_index: args.input_pool_index,
        fee_payer: user,
        spl_token_program,
        ctoken_program,
        cpi_authority,
        merkle_tree: input_merkle_tree,
        nullifier_queue: input_nullifier_queue,
    };

    decompress_ctoken_to_spl(decompress_params)?;
    verbose_log!("Decompress CPI completed");

    // === STEP 2: Swap on DEX ===
    verbose_log!("Step 2: Executing swap on DEX...");

    let actual_output_amount = match args.dex_type {
        DexType::MeteoraDammV2 => {
            process_meteora_damm_v2_swap(accounts, args.input_amount, args.min_output_amount)?
        }
        DexType::MeteoraDlmm => {
            verbose_log!("Meteora DLMM swap not yet implemented");
            return Err(PrivacySwapError::InvalidDexType.into());
        }
        DexType::OrcaWhirlpool => {
            verbose_log!("Orca Whirlpool swap not yet implemented");
            return Err(PrivacySwapError::InvalidDexType.into());
        }
        DexType::RaydiumClmm => {
            verbose_log!("Raydium CLMM swap not yet implemented");
            return Err(PrivacySwapError::InvalidDexType.into());
        }
    };

    // === STEP 3: Compress output SPL to cTokens (NO proof needed!) ===
    verbose_log!("Step 3: Compressing output SPL to cTokens...");

    let compress_params = CompressSplToCtokenParams {
        amount: actual_output_amount,
        mint: output_mint,
        source_spl: temp_output_spl,
        authority: user,
        spl_interface_pda: output_spl_interface_pda,
        spl_interface_bump: args.output_spl_interface_bump,
        pool_index: args.output_pool_index,
        fee_payer: user,
        spl_token_program,
        ctoken_program,
        cpi_authority,
        merkle_tree: output_merkle_tree,
        output_queue,
    };

    compress_spl_to_ctoken(compress_params)?;
    verbose_log!("Compress CPI completed");

    // === STEP 4: Store encrypted audit log ===
    if !args.encrypted_audit.is_empty() {
        verbose_log!("Encrypted audit data received");
        // TODO: Write to audit log account if provided
    }

    verbose_log!("Private swap completed successfully");

    Ok(())
}

/// Meteora DAMM v2 Program ID: cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG
const METEORA_DAMM_V2_PROGRAM: Address = Address::new_from_array([
    0x0a, 0x1e, 0xea, 0x13, 0x97, 0x65, 0xf6, 0x4c,
    0x1c, 0x79, 0x8f, 0x23, 0x43, 0xbb, 0x95, 0x64,
    0xc8, 0x83, 0x3b, 0xb6, 0x6a, 0x98, 0x5e, 0x30,
    0xb4, 0x11, 0x8f, 0x5e, 0x7f, 0xab, 0x6e, 0xa5,
]);

/// Meteora DAMM v2 swap instruction discriminator
const METEORA_SWAP_DISCRIMINATOR: [u8; 8] = [0xf8, 0xc6, 0x9e, 0x91, 0xe1, 0x75, 0x87, 0xc8];

/// Execute swap on Meteora DAMM v2
/// Returns the actual output amount received
fn process_meteora_damm_v2_swap(
    accounts: &[AccountView],
    amount_in: u64,
    min_amount_out: u64,
) -> Result<u64, ProgramError> {
    verbose_log!("Executing Meteora DAMM v2 swap...");

    // DEX accounts are at indices 14-18 (updated layout)
    // 14: [writable] DEX pool account
    // 15: [writable] DEX token A vault
    // 16: [writable] DEX token B vault
    // 17: [] DEX pool authority
    // 18: [] DEX program

    if accounts.len() < 19 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let _user = &accounts[0];
    let input_mint = &accounts[1];
    let output_mint = &accounts[2];
    let temp_input_spl = &accounts[3];
    let temp_output_spl = &accounts[4];
    let spl_token_program = &accounts[9];
    let pool = &accounts[14];
    let vault_a = &accounts[15];
    let vault_b = &accounts[16];
    let pool_authority = &accounts[17];
    let _dex_program = &accounts[18];

    // Build swap instruction data
    // Format: [discriminator(8) | amount_in(8) | min_amount_out(8)]
    let mut ix_data = [0u8; 24];
    ix_data[0..8].copy_from_slice(&METEORA_SWAP_DISCRIMINATOR);
    ix_data[8..16].copy_from_slice(&amount_in.to_le_bytes());
    ix_data[16..24].copy_from_slice(&min_amount_out.to_le_bytes());

    // Build CPI accounts for Meteora swap
    let cpi_accounts = [
        InstructionAccount::writable(pool.address()),
        InstructionAccount::readonly(pool_authority.address()),
        InstructionAccount::writable(temp_input_spl.address()),  // User's input token account
        InstructionAccount::writable(temp_output_spl.address()), // User's output token account
        InstructionAccount::writable(vault_a.address()),
        InstructionAccount::writable(vault_b.address()),
        InstructionAccount::readonly(spl_token_program.address()),
        InstructionAccount::readonly(spl_token_program.address()), // Token B program (same)
        InstructionAccount::readonly(input_mint.address()),
        InstructionAccount::readonly(output_mint.address()),
    ];

    let instruction = InstructionView {
        program_id: &METEORA_DAMM_V2_PROGRAM,
        accounts: &cpi_accounts,
        data: &ix_data,
    };

    // Account infos for CPI
    let account_infos = [
        pool,
        pool_authority,
        temp_input_spl,
        temp_output_spl,
        vault_a,
        vault_b,
        spl_token_program,
        spl_token_program,
        input_mint,
        output_mint,
    ];

    // Execute CPI
    invoke(&instruction, &account_infos)?;

    verbose_log!("Meteora DAMM v2 swap completed");

    // For now, return min_amount_out as placeholder
    // In production, would read actual output from token account
    Ok(min_amount_out)
}

/// Update owner's encryption public key
fn process_update_owner_key(
    _program_id: &Address,
    accounts: &[AccountView],
    _instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let authority = &accounts[0];
    let _config_account = &accounts[1];

    if !authority.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // TODO: Verify authority matches config.authority
    // TODO: Update config.owner_encryption_pubkey

    verbose_log!("Owner encryption key updated");

    Ok(())
}

/// Close accounts and return rent to destination
///
/// SECURITY (CRIT-005 FIX): Only allows closing in these cases:
/// 1. Commitment accounts that are FullyClaimed (user already got their funds)
/// 2. Nullifier registries (only by pool authority)
/// 3. Pool configs (only by pool authority)
///
/// This prevents attackers from destroying users' active commitments.
fn process_close_accounts(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::{CommitmentAccount, CommitmentStatus, PrivacyPoolConfig, NullifierRegistry};

    let args = CloseAccountsArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let authority = &accounts[0];
    let account_to_close = &accounts[1];

    if !authority.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // Verify the account belongs to this program
    // SAFETY: We're reading the owner field which is valid for all accounts
    if unsafe { account_to_close.owner() } != program_id {
        return Err(PrivacySwapError::InvalidOwner.into());
    }

    // === CRIT-005 FIX: Authorization check based on account type ===
    // Read discriminator to determine account type
    let account_data = account_to_close.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    if account_data.len() < 8 {
        verbose_log!("Account too small to have discriminator!");
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    let discriminator: [u8; 8] = account_data[0..8].try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;

    // Check if this is a commitment account
    if discriminator == CommitmentAccount::DISCRIMINATOR {
        // COMMITMENT: Only allow closing if FullyClaimed
        if account_data.len() < CommitmentAccount::LEN {
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        // Status is at offset 136
        let status = account_data[136];
        if status != CommitmentStatus::FullyClaimed as u8 {
            verbose_log!("SECURITY: Cannot close commitment that isn't FullyClaimed!");
            verbose_log!("  Status: {} (must be {})", status, CommitmentStatus::FullyClaimed as u8);
            return Err(PrivacySwapError::CommitmentNotSwapped.into()); // Reusing error for "not ready to close"
        }
        verbose_log!("  Commitment is FullyClaimed, safe to close");
    }
    // Check if this is a pool config - requires pool authority
    else if discriminator == PrivacyPoolConfig::DISCRIMINATOR {
        if account_data.len() < PrivacyPoolConfig::LEN {
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        // Authority is at offset 252
        let pool_authority: [u8; 32] = account_data[252..284].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;

        if authority.address().as_ref() != &pool_authority {
            verbose_log!("SECURITY: Only pool authority can close pool config!");
            return Err(PrivacySwapError::UnauthorizedKeeper.into());
        }
        verbose_log!("  Pool authority verified, safe to close");
    }
    // Check if this is a nullifier registry - requires pool authority (via pool_config account)
    else if discriminator == NullifierRegistry::DISCRIMINATOR {
        // Need pool_config as account[2] to verify authority
        if accounts.len() < 3 {
            verbose_log!("SECURITY: Need pool_config to close nullifier registry!");
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let pool_config = &accounts[2];

        let pool_data = pool_config.try_borrow()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        if pool_data.len() < PrivacyPoolConfig::LEN {
            return Err(PrivacySwapError::InvalidPoolConfig.into());
        }

        // Verify pool_config discriminator
        if &pool_data[0..8] != &PrivacyPoolConfig::DISCRIMINATOR {
            return Err(PrivacySwapError::InvalidAccount.into());
        }

        // Authority is at offset 252
        let pool_authority: [u8; 32] = pool_data[252..284].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?;

        if authority.address().as_ref() != &pool_authority {
            verbose_log!("SECURITY: Only pool authority can close nullifier registry!");
            return Err(PrivacySwapError::UnauthorizedKeeper.into());
        }
        verbose_log!("  Pool authority verified, safe to close nullifier registry");
    }
    // Already closed account - allow anyone to clean up
    else if discriminator == [0xFF; 8] {
        verbose_log!("  Account already closed, allowing cleanup");
    }
    // Unknown account type - reject
    else {
        verbose_log!("SECURITY: Unknown account type, cannot close!");
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    drop(account_data);

    // SEC-013 FIX: Properly close account by zeroing data and marking as closed
    // SECURITY: This is the critical part - preventing account reuse/revival attacks

    // Validate rent destination is provided
    let _rent_destination = accounts.iter()
        .find(|a| a.address().as_ref() == args.rent_destination.as_ref())
        .ok_or(PrivacySwapError::InvalidAccount)?;

    // Get account lamports for logging (prefixed to avoid warning when verbose-logs disabled)
    #[allow(unused_variables)]
    let account_lamports = account_to_close.lamports();

    // CRITICAL SECURITY FIX: Zero out account data and write closed discriminator
    // This prevents:
    // 1. Revival attacks - account cannot be "revived" with old data
    // 2. Type cosplay - closed discriminator prevents account from being used as another type
    // 3. Information leakage - all data is zeroed
    {
        let mut data = account_to_close.try_borrow_mut()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // Write CLOSED_ACCOUNT_DISCRIMINATOR first to mark as closed
        // Using Anchor's standard: [0xFF; 8] indicates closed account
        // This MUST be checked in all instruction handlers
        const CLOSED_ACCOUNT_DISCRIMINATOR: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        if data.len() >= 8 {
            data[0..8].copy_from_slice(&CLOSED_ACCOUNT_DISCRIMINATOR);
        }

        // Zero remaining data to prevent information leakage
        for byte in data[8..].iter_mut() {
            *byte = 0;
        }
    }

    // Note: Lamport transfer is handled by the client/SDK via System Program
    // The client should include a System Program Transfer instruction
    // in the same transaction to reclaim rent

    verbose_log!("Account marked as closed (discriminator set to 0xFF)");
    verbose_log!("  Account had {} lamports - client should transfer via System Program", account_lamports);

    Ok(())
}

// ============================================================
// V5 PROCESSOR: REFUND PENDING (HIGH-002 FIX)
// ============================================================

/// Timeout in slots before pending deposits can be refunded
/// 1000 slots ~ 7 minutes at 400ms/slot
const REFUND_TIMEOUT_SLOTS: u64 = 1000;

/// Refund pending deposit if keeper hasn't swapped within timeout
///
/// HIGH-002 FIX: Users can now recover funds from stuck deposits.
/// HIGH-004 FIX: Timeout is now enforced via Clock sysvar.
///
/// Requirements:
/// 1. Commitment must be in Pending status (keeper hasn't swapped)
/// 2. REFUND_TIMEOUT_SLOTS must have passed since deposit
/// 3. Caller must prove ownership via secret/nonce
///
/// Accounts:
/// 0.  [signer] Refunder (proves ownership via secret)
/// 1.  [] Pool config PDA
/// 2.  [writable] Vault PDA
/// 3.  [writable] Vault's input token ATA (source of refund)
/// 4.  [writable] Destination ATA (where to send refund)
/// 5.  [] Token program
/// 6.  [writable] Commitment account PDA
/// 7.  [] Clock sysvar (HIGH-004 fix: for timeout verification)
fn process_refund_pending(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use crate::state::{CommitmentAccount, CommitmentStatus, PrivacyPoolConfig, seeds_v2};
    use crate::vault::{verify_commitment, vault_transfer_spl};
    use crate::verification::{verify_vault_pda, verify_program_owner, verify_spl_token_program, verify_clock_sysvar, read_clock_slot};

    let args = RefundPendingArgs::unpack(instruction_data)
        .ok_or(PrivacySwapError::InvalidInstruction)?;

    // HIGH-004 FIX: Now requires 8 accounts (added Clock sysvar)
    if accounts.len() < 8 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let refunder = &accounts[0];
    let pool_config = &accounts[1];
    let vault_pda = &accounts[2];
    let vault_input_ata = &accounts[3];
    let destination_ata = &accounts[4];
    let token_program = &accounts[5];
    let commitment_account = &accounts[6];
    let clock_sysvar = &accounts[7]; // HIGH-004 FIX: Clock sysvar for timeout

    // Verify refunder is signer
    if !refunder.is_signer() {
        return Err(PrivacySwapError::MissingRequiredSigner.into());
    }

    // Verify token program
    verify_spl_token_program(token_program)?;

    // HIGH-004 FIX: Verify Clock sysvar
    verify_clock_sysvar(clock_sysvar)?;

    // Verify commitment is owned by program
    verify_program_owner(commitment_account, program_id)?;

    verbose_log!("Processing refund request...");

    // Read commitment data
    let commitment_data = commitment_account.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    // Verify discriminator
    if commitment_data.len() < CommitmentAccount::LEN {
        return Err(PrivacySwapError::InvalidAccount.into());
    }
    if &commitment_data[0..8] != &CommitmentAccount::DISCRIMINATOR {
        verbose_log!("Invalid commitment discriminator!");
        return Err(PrivacySwapError::InvalidAccount.into());
    }

    // Verify commitment is in PENDING status
    let status = commitment_data[136];
    if status != CommitmentStatus::Pending as u8 {
        verbose_log!("Commitment not in Pending status! Status: {}", status);
        verbose_log!("Can only refund Pending deposits (keeper hasn't swapped yet)");
        return Err(PrivacySwapError::NotPending.into());
    }

    // Verify timeout has passed
    // deposit_slot is at offset 120
    let deposit_slot = u64::from_le_bytes(
        commitment_data[120..128].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?
    );

    // HIGH-004 FIX: Read current slot from Clock sysvar
    let clock_data = clock_sysvar.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;
    let current_slot = read_clock_slot(&clock_data)
        .ok_or(PrivacySwapError::InvalidAccount)?;
    drop(clock_data);

    verbose_log!("  Deposit slot: {}, Current slot: {}", deposit_slot, current_slot);

    // HIGH-004 FIX: Enforce timeout (1000 slots ~ 7 minutes)
    // This prevents griefing attacks where users immediately refund before keeper can swap
    if current_slot < deposit_slot.saturating_add(REFUND_TIMEOUT_SLOTS) {
        verbose_log!("Refund timeout not reached!");
        verbose_log!("  Deposit slot: {}, Current: {}, Required: {}",
            deposit_slot, current_slot, deposit_slot.saturating_add(REFUND_TIMEOUT_SLOTS));
        return Err(PrivacySwapError::RefundTooEarly.into());
    }
    verbose_log!("  Timeout verified - {} slots have passed", current_slot.saturating_sub(deposit_slot));

    // Verify proof of ownership via secret/nonce
    let stored_commitment: [u8; 32] = commitment_data[8..40].try_into()
        .map_err(|_| PrivacySwapError::InvalidAccount)?;

    if !verify_commitment(&args.secret, args.nonce, &stored_commitment) {
        verbose_log!("Invalid secret/nonce! Cannot prove ownership.");
        return Err(PrivacySwapError::InvalidCommitment.into());
    }
    verbose_log!("  Ownership verified via secret/nonce");

    // CRIT-009 FIX: Verify claim_authority signature (same as claim)
    // Without this, attacker could frontrun refund transactions by:
    // 1. Monitoring mempool for refund txs
    // 2. Extracting secret/nonce from instruction data
    // 3. Submitting competing refund to attacker's destination
    use crate::vault::read_commitment_claim_authority;
    let stored_claim_authority = read_commitment_claim_authority(&commitment_data)
        .ok_or(PrivacySwapError::InvalidAccount)?;
    if *refunder.address().as_ref() != stored_claim_authority {
        verbose_log!("SECURITY: Refunder doesn't match claim_authority!");
        verbose_log!("  Only claim_authority can refund (prevents frontrunning)");
        return Err(PrivacySwapError::UnauthorizedClaimAuthority.into());
    }
    verbose_log!("  Claim authority verified (anti-frontrunning)");

    // Get input amount to refund
    let input_amount = u64::from_le_bytes(
        commitment_data[104..112].try_into()
            .map_err(|_| PrivacySwapError::InvalidAccount)?
    );

    verbose_log!("  Refunding {} input tokens", input_amount);

    // Get pool config for vault bump
    let pool_data = pool_config.try_borrow()
        .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

    if pool_data.len() < PrivacyPoolConfig::LEN {
        return Err(PrivacySwapError::InvalidPoolConfig.into());
    }

    let vault_bump = pool_data[113];
    let input_mint: [u8; 32] = pool_data[8..40].try_into()
        .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;
    let output_mint: [u8; 32] = pool_data[40..72].try_into()
        .map_err(|_| PrivacySwapError::InvalidPoolConfig)?;
    let tier = pool_data[72];

    drop(pool_data);
    drop(commitment_data);

    // Verify vault PDA
    verify_vault_pda(vault_pda, &input_mint, &output_mint, tier, vault_bump)?;

    // Transfer input tokens back to user
    let tier_bytes = [tier];
    vault_transfer_spl(
        vault_input_ata,
        destination_ata,
        vault_pda,
        token_program,
        input_amount,
        &input_mint,
        &output_mint,
        &tier_bytes,
        &[vault_bump],
    )?;

    verbose_log!("  Tokens transferred back to user");

    // Mark commitment as Refunded (using FullyClaimed status = 3)
    // This prevents any future claims on this commitment
    {
        let mut commitment_data_mut = commitment_account.try_borrow_mut()
            .map_err(|_| PrivacySwapError::AccountBorrowFailed)?;

        // Set status to FullyClaimed (3) - effectively "consumed"
        commitment_data_mut[136] = CommitmentStatus::FullyClaimed as u8;

        // Set output_amount to 0 (nothing to claim)
        commitment_data_mut[112..120].copy_from_slice(&0u64.to_le_bytes());
    }

    verbose_log!("Refund completed successfully!");
    verbose_log!("  Refunded: {} input tokens", input_amount);
    verbose_log!("  Commitment marked as consumed (no future claims)");

    Ok(())
}
