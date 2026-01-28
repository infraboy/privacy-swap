//! Privacy Swap Program
//!
//! A ZK-secure private swap program using Light Protocol compressed tokens
//! and Pinocchio for efficient on-chain execution.
//!
//! Flow:
//! 1. Decompress input tokens (Light Protocol - write mode)
//! 2. Swap on external DEX (Meteora DAMM v2)
//! 3. Compress output tokens (Light Protocol - execute mode)
//! 4. Store encrypted audit log

#![no_std]

extern crate alloc;

use pinocchio::{
    AccountView,
    Address,
    entrypoint,
    nostd_panic_handler,
    ProgramResult,
};

pub mod error;
pub mod instruction;
pub mod light_cpi;
pub mod processor;
pub mod state;
pub mod vault;
pub mod verification;

// Program ID: 6Hf7GVAF8XizDn9xHoUJuv4RgaSTe1rJBNSe3cdzHWqa (devnet)
pub const ID: Address = Address::new_from_array([
    0x4e, 0x8e, 0xd1, 0x05, 0x5f, 0xbe, 0xd2, 0xfd,
    0x7d, 0x5f, 0x30, 0xba, 0x99, 0xd4, 0x3d, 0x76,
    0x48, 0xf0, 0x7b, 0xad, 0xc9, 0x43, 0x98, 0xe6,
    0xb3, 0x92, 0x83, 0x41, 0xc3, 0x0d, 0x30, 0x65,
]);

// Set up panic handler for no_std
nostd_panic_handler!();

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    processor::process(program_id, accounts, instruction_data)
}
