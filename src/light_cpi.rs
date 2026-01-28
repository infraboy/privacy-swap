//! Light Protocol CPI module for Pinocchio
//!
//! This module provides raw instruction building for Light Protocol's
//! compressed token program, compatible with Pinocchio's AccountView.
//!
//! Key insight: Decompress requires a validity proof, compress does NOT.

use alloc::vec::Vec;
use pinocchio::{
    AccountView,
    Address,
    ProgramResult,
};
use solana_instruction_view::{
    cpi::invoke,
    InstructionAccount, InstructionView,
};

use crate::instruction::{CompressedProof, MerkleContext};

// ============================================================
// CONSTANTS
// ============================================================

/// Light Protocol Compressed Token Program ID
/// cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
pub const CTOKEN_PROGRAM_ID: Address = Address::new_from_array([
    0x09, 0x15, 0xa3, 0x57, 0x23, 0x79, 0x4e, 0x8f,
    0xb6, 0x5d, 0x07, 0x5b, 0x6b, 0x72, 0x69, 0x9c,
    0x38, 0xdd, 0x02, 0xe5, 0x94, 0x8b, 0x75, 0xb0,
    0xe5, 0xa0, 0x41, 0x8e, 0x80, 0x97, 0x5b, 0x44,
]);

/// Light Protocol CPI Authority PDA
/// GXtd2izAiMJPwMEjfgTRH3d7k9mjn4Jq3JrWFv9gySYy
pub const CPI_AUTHORITY_PDA: Address = Address::new_from_array([
    0xe6, 0xc9, 0x18, 0xb0, 0xbd, 0x7c, 0xcf, 0x91,
    0x54, 0x44, 0x8a, 0x7a, 0xbf, 0x6a, 0x8f, 0x39,
    0x78, 0x29, 0xa1, 0xe8, 0xfd, 0x08, 0xa7, 0xf0,
    0xd0, 0xb3, 0xaa, 0xb8, 0x78, 0x52, 0xfc, 0x32,
]);

/// Transfer2 instruction discriminator
pub const TRANSFER2_DISCRIMINATOR: u8 = 101;

/// Compression modes
pub const COMPRESS_MODE: u8 = 0;
pub const DECOMPRESS_MODE: u8 = 1;

// ============================================================
// COMPRESSION STRUCT
// ============================================================

/// Compression operation for Transfer2 instruction
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Compression {
    pub mode: u8,              // 0=Compress, 1=Decompress
    pub amount: u64,           // Amount in smallest units
    pub mint: u8,              // Index in packed_accounts
    pub source_or_recipient: u8,
    pub authority: u8,
    pub pool_account_index: u8,
    pub pool_index: u8,
    pub bump: u8,
    pub decimals: u8,
}

impl Compression {
    /// Create compress operation for cToken (burns from ctoken account)
    pub fn compress_ctoken(amount: u64, mint: u8, source: u8, authority: u8) -> Self {
        Compression {
            mode: COMPRESS_MODE,
            amount,
            mint,
            source_or_recipient: source,
            authority,
            pool_account_index: 0,
            pool_index: 0,
            bump: 0,
            decimals: 0,
        }
    }

    /// Create decompress operation for SPL (mints to SPL account from pool)
    pub fn decompress_spl(
        amount: u64,
        mint: u8,
        recipient: u8,
        pool_account_index: u8,
        pool_index: u8,
        bump: u8,
    ) -> Self {
        Compression {
            mode: DECOMPRESS_MODE,
            amount,
            mint,
            source_or_recipient: recipient,
            authority: 0,
            pool_account_index,
            pool_index,
            bump,
            decimals: 0,
        }
    }

    /// Create compress operation for SPL (transfers to pool)
    pub fn compress_spl(
        amount: u64,
        mint: u8,
        source: u8,
        authority: u8,
        pool_account_index: u8,
        pool_index: u8,
        bump: u8,
    ) -> Self {
        Compression {
            mode: COMPRESS_MODE,
            amount,
            mint,
            source_or_recipient: source,
            authority,
            pool_account_index,
            pool_index,
            bump,
            decimals: 0,
        }
    }

    /// Create decompress operation for cToken (mints to ctoken account)
    pub fn decompress_ctoken(amount: u64, mint: u8, recipient: u8) -> Self {
        Compression {
            mode: DECOMPRESS_MODE,
            amount,
            mint,
            source_or_recipient: recipient,
            authority: 0,
            pool_account_index: 0,
            pool_index: 0,
            bump: 0,
            decimals: 0,
        }
    }
}

// ============================================================
// TRANSFER2 INSTRUCTION DATA BUILDER
// ============================================================

/// Build Transfer2 instruction data for decompress operations WITH proof
///
/// Decompress requires a validity proof to prove ownership of compressed tokens.
/// The proof is obtained from the Light Protocol indexer.
pub fn build_transfer2_decompress_data_with_proof(
    compressions: &[Compression],
    proof: &CompressedProof,
    merkle_context: &MerkleContext,
    amount: u64,
    owner_index: u8,
) -> Vec<u8> {
    // Estimate size: ~300 bytes for decompress with proof
    let mut data = Vec::with_capacity(350);

    // Discriminator
    data.push(TRANSFER2_DISCRIMINATOR);

    // with_transaction_hash: bool (false)
    data.push(0);

    // with_lamports_change_account_merkle_tree_index: bool (false)
    data.push(0);

    // lamports_change_account_merkle_tree_index: u8 (0)
    data.push(0);

    // lamports_change_account_owner_index: u8 (0)
    data.push(0);

    // output_queue: u8 (0 - not used for decompress-only)
    data.push(0);

    // max_top_up: u16 (0 = no limit)
    data.extend_from_slice(&0u16.to_le_bytes());

    // cpi_context: Option<CompressedCpiContext> (None = 0)
    data.push(0);

    // compressions: Option<Vec<Compression>> (Some)
    data.push(1); // Some
    data.extend_from_slice(&(compressions.len() as u32).to_le_bytes()); // length
    for compression in compressions {
        // Serialize each compression (mode as u8 enum, then fields)
        data.push(compression.mode);
        data.extend_from_slice(&compression.amount.to_le_bytes());
        data.push(compression.mint);
        data.push(compression.source_or_recipient);
        data.push(compression.authority);
        data.push(compression.pool_account_index);
        data.push(compression.pool_index);
        data.push(compression.bump);
        data.push(compression.decimals);
    }

    // proof: Option<CompressedProof> (Some = 1)
    data.push(1);
    data.extend_from_slice(&proof.a);
    data.extend_from_slice(&proof.b);
    data.extend_from_slice(&proof.c);

    // in_token_data: Vec<MultiInputTokenDataWithContext>
    // We have 1 input token with merkle context
    data.extend_from_slice(&1u32.to_le_bytes()); // length = 1

    // MultiInputTokenDataWithContext:
    // - amount: u64
    data.extend_from_slice(&amount.to_le_bytes());
    // - delegated_amount: Option<u64> (None = 0)
    data.push(0);
    // - is_native: Option<u64> (None = 0)
    data.push(0);
    // - merkle_context: PackedMerkleContext
    //   - merkle_tree_pubkey_index: u8
    data.push(merkle_context.merkle_tree_index);
    //   - nullifier_queue_pubkey_index: u8
    data.push(merkle_context.queue_index);
    //   - leaf_index: u32
    data.extend_from_slice(&merkle_context.leaf_index.to_le_bytes());
    //   - prove_by_index: bool (true = use root_index)
    data.push(1);
    // - root_index: u16
    data.extend_from_slice(&merkle_context.root_index.to_le_bytes());
    // - owner_index: u8
    data.push(owner_index);
    // - tlv_elements: Option<Vec<TlvDataElement>> (None = 0)
    data.push(0);

    // out_token_data: Vec<MultiTokenTransferOutputData> (empty for decompress-only)
    data.extend_from_slice(&0u32.to_le_bytes());

    // in_lamports: Option<Vec<u64>> (None)
    data.push(0);

    // out_lamports: Option<Vec<u64>> (None)
    data.push(0);

    // in_tlv: Option<Vec<Vec<u8>>> (None)
    data.push(0);

    // out_tlv: Option<Vec<Vec<u8>>> (None)
    data.push(0);

    data
}

/// Build Transfer2 instruction data for compress operations (NO proof needed)
///
/// Compress does NOT require a proof - tokens are entering compressed state.
pub fn build_transfer2_compress_data(compressions: &[Compression]) -> Vec<u8> {
    // Estimate size: ~64 bytes for compress without proof
    let mut data = Vec::with_capacity(64 + compressions.len() * 19);

    // Discriminator
    data.push(TRANSFER2_DISCRIMINATOR);

    // with_transaction_hash: bool (false)
    data.push(0);

    // with_lamports_change_account_merkle_tree_index: bool (false)
    data.push(0);

    // lamports_change_account_merkle_tree_index: u8 (0)
    data.push(0);

    // lamports_change_account_owner_index: u8 (0)
    data.push(0);

    // output_queue: u8 (0)
    data.push(0);

    // max_top_up: u16 (0 = no limit)
    data.extend_from_slice(&0u16.to_le_bytes());

    // cpi_context: Option<CompressedCpiContext> (None = 0)
    data.push(0);

    // compressions: Option<Vec<Compression>> (Some)
    data.push(1); // Some
    data.extend_from_slice(&(compressions.len() as u32).to_le_bytes()); // length
    for compression in compressions {
        data.push(compression.mode);
        data.extend_from_slice(&compression.amount.to_le_bytes());
        data.push(compression.mint);
        data.push(compression.source_or_recipient);
        data.push(compression.authority);
        data.push(compression.pool_account_index);
        data.push(compression.pool_index);
        data.push(compression.bump);
        data.push(compression.decimals);
    }

    // proof: Option<CompressedProof> (None = 0 for compress)
    data.push(0);

    // in_token_data: Vec (empty for compress)
    data.extend_from_slice(&0u32.to_le_bytes());

    // out_token_data: Vec (empty for compress via compressions array)
    data.extend_from_slice(&0u32.to_le_bytes());

    // in_lamports: Option (None)
    data.push(0);

    // out_lamports: Option (None)
    data.push(0);

    // in_tlv: Option (None)
    data.push(0);

    // out_tlv: Option (None)
    data.push(0);

    data
}

// ============================================================
// CPI HELPERS
// ============================================================

/// Parameters for decompress cToken to SPL operation
pub struct DecompressCTokenToSplParams<'a> {
    pub amount: u64,
    pub proof: &'a CompressedProof,
    pub merkle_context: &'a MerkleContext,
    pub mint: &'a AccountView,
    pub source_ctoken: &'a AccountView,
    pub destination_spl: &'a AccountView,
    pub authority: &'a AccountView,
    pub spl_interface_pda: &'a AccountView,
    pub spl_interface_bump: u8,
    pub pool_index: u8,
    pub fee_payer: &'a AccountView,
    pub spl_token_program: &'a AccountView,
    pub ctoken_program: &'a AccountView,
    pub cpi_authority: &'a AccountView,
    pub merkle_tree: &'a AccountView,
    pub nullifier_queue: &'a AccountView,
}

/// Invoke decompress cToken to SPL via CPI
///
/// This performs the decompress operation with ZK proof validation.
/// The proof proves ownership of the compressed tokens.
pub fn decompress_ctoken_to_spl<'a>(
    params: DecompressCTokenToSplParams<'a>,
) -> ProgramResult {
    // Build compression operations
    // Account indices in packed_accounts (after cpi_authority and fee_payer):
    // 0: mint
    // 1: destination SPL token account
    // 2: authority (signer/owner)
    // 3: SPL interface PDA (token pool)
    // 4: SPL Token program
    // 5: merkle tree
    // 6: nullifier queue

    let compressions = [
        // Decompress from pool to SPL account
        Compression::decompress_spl(
            params.amount,
            0, // mint index in packed_accounts
            1, // destination SPL index
            3, // pool account index (SPL interface PDA)
            params.pool_index,
            params.spl_interface_bump,
        ),
    ];

    // Build instruction data with proof
    // owner_index = 2 (authority position in packed_accounts)
    let data = build_transfer2_decompress_data_with_proof(
        &compressions,
        params.proof,
        params.merkle_context,
        params.amount,
        2, // owner_index in packed_accounts
    );

    // Build account list for CPI
    // Order: cpi_authority_pda, fee_payer, packed_accounts...
    let accounts = [
        InstructionAccount::readonly(params.cpi_authority.address()),
        InstructionAccount::writable_signer(params.fee_payer.address()),
        // Packed accounts
        InstructionAccount::readonly(params.mint.address()),                   // 0
        InstructionAccount::writable(params.destination_spl.address()),        // 1
        InstructionAccount::readonly_signer(params.authority.address()),       // 2
        InstructionAccount::writable(params.spl_interface_pda.address()),      // 3
        InstructionAccount::readonly(params.spl_token_program.address()),      // 4
        InstructionAccount::writable(params.merkle_tree.address()),            // 5
        InstructionAccount::writable(params.nullifier_queue.address()),        // 6
    ];

    // Create instruction view
    let instruction = InstructionView {
        program_id: &CTOKEN_PROGRAM_ID,
        accounts: &accounts,
        data: &data,
    };

    // Collect account infos for CPI
    let account_infos = [
        params.cpi_authority,
        params.fee_payer,
        params.mint,
        params.destination_spl,
        params.authority,
        params.spl_interface_pda,
        params.spl_token_program,
        params.merkle_tree,
        params.nullifier_queue,
        params.ctoken_program,
    ];

    // Invoke CPI (user is already a signer on the transaction)
    invoke(&instruction, &account_infos)
}

/// Parameters for compress SPL to cToken operation
/// NOTE: Compress does NOT require a proof - simpler operation
pub struct CompressSplToCtokenParams<'a> {
    pub amount: u64,
    pub mint: &'a AccountView,
    pub source_spl: &'a AccountView,
    pub authority: &'a AccountView,
    pub spl_interface_pda: &'a AccountView,
    pub spl_interface_bump: u8,
    pub pool_index: u8,
    pub fee_payer: &'a AccountView,
    pub spl_token_program: &'a AccountView,
    pub ctoken_program: &'a AccountView,
    pub cpi_authority: &'a AccountView,
    pub merkle_tree: &'a AccountView,
    pub output_queue: &'a AccountView,
}

/// Invoke compress SPL to cToken via CPI
///
/// Compress operation - transfers SPL tokens to Light Protocol pool,
/// creating new compressed tokens for the user.
///
/// NOTE: NO PROOF NEEDED for compress - tokens are entering compressed state.
pub fn compress_spl_to_ctoken<'a>(
    params: CompressSplToCtokenParams<'a>,
) -> ProgramResult {
    // Build compression operations
    // Account indices in packed_accounts (after cpi_authority and fee_payer):
    // 0: mint
    // 1: source SPL token account
    // 2: authority (signer)
    // 3: SPL interface PDA (token pool)
    // 4: SPL Token program
    // 5: merkle tree
    // 6: output queue

    let compressions = [
        // Compress from SPL to pool
        Compression::compress_spl(
            params.amount,
            0, // mint index
            1, // source SPL index
            2, // authority index
            3, // pool account index (SPL interface PDA)
            params.pool_index,
            params.spl_interface_bump,
        ),
    ];

    // Build instruction data (NO proof for compress!)
    let data = build_transfer2_compress_data(&compressions);

    // Build account list for CPI
    let accounts = [
        InstructionAccount::readonly(params.cpi_authority.address()),
        InstructionAccount::writable_signer(params.fee_payer.address()),
        // Packed accounts
        InstructionAccount::readonly(params.mint.address()),                   // 0
        InstructionAccount::writable(params.source_spl.address()),             // 1
        InstructionAccount::readonly_signer(params.authority.address()),       // 2
        InstructionAccount::writable(params.spl_interface_pda.address()),      // 3
        InstructionAccount::readonly(params.spl_token_program.address()),      // 4
        InstructionAccount::writable(params.merkle_tree.address()),            // 5
        InstructionAccount::writable(params.output_queue.address()),           // 6
    ];

    // Create instruction view
    let instruction = InstructionView {
        program_id: &CTOKEN_PROGRAM_ID,
        accounts: &accounts,
        data: &data,
    };

    // Collect account infos for CPI
    let account_infos = [
        params.cpi_authority,
        params.fee_payer,
        params.mint,
        params.source_spl,
        params.authority,
        params.spl_interface_pda,
        params.spl_token_program,
        params.merkle_tree,
        params.output_queue,
        params.ctoken_program,
    ];

    // Invoke CPI (user is already a signer on the transaction)
    invoke(&instruction, &account_infos)
}
