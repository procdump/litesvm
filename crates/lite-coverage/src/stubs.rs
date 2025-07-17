use std::sync::{Arc, RwLock};

use solana_program_error::ProgramResult;
use solana_program_stubs::declare_sol_loader_stubsv2;
use solana_sysvar::program_stubs::SyscallStubs;

use solana_instruction::Instruction;
use solana_program::instruction::AccountMeta;
use solana_pubkey::Pubkey;
use solana_sysvar::slot_history::AccountInfo;

declare_sol_loader_stubsv2!();

/// Main logic behind the StubsManager is explained in loader::adjust_stubs.
pub struct StubsManager;
impl StubsManager {
    pub(crate) fn my_set_syscall_stubs(
        syscall_stubs: Box<dyn SyscallStubs>,
    ) -> Box<dyn SyscallStubs> {
        std::mem::replace(&mut SYSCALL_STUBS.write().unwrap(), syscall_stubs)
    }
}

pub struct WrapperSyscallStubs {}
impl SyscallStubs for WrapperSyscallStubs {
    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        SYSCALL_STUBS.read().unwrap().sol_get_clock_sysvar(var_addr)
    }
    fn sol_get_epoch_rewards_sysvar(&self, var_addr: *mut u8) -> u64 {
        SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_get_epoch_rewards_sysvar(var_addr)
    }
    fn sol_get_epoch_schedule_sysvar(&self, var_addr: *mut u8) -> u64 {
        SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_get_epoch_schedule_sysvar(var_addr)
    }
    fn sol_get_fees_sysvar(&self, var_addr: *mut u8) -> u64 {
        SYSCALL_STUBS.read().unwrap().sol_get_fees_sysvar(var_addr)
    }
    fn sol_get_last_restart_slot(&self, var_addr: *mut u8) -> u64 {
        SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_get_last_restart_slot(var_addr)
    }
    fn sol_get_processed_sibling_instruction(&self, index: usize) -> Option<Instruction> {
        SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_get_processed_sibling_instruction(index)
    }
    fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
        SYSCALL_STUBS.read().unwrap().sol_get_rent_sysvar(var_addr)
    }
    fn sol_get_return_data(&self) -> Option<(Pubkey, Vec<u8>)> {
        SYSCALL_STUBS.read().unwrap().sol_get_return_data()
    }
    fn sol_get_stack_height(&self) -> u64 {
        SYSCALL_STUBS.read().unwrap().sol_get_stack_height()
    }
    fn sol_invoke_signed(
        &self,
        instruction: &Instruction,
        account_infos: &[AccountInfo],
        signers_seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_invoke_signed(instruction, account_infos, signers_seeds)
    }
    fn sol_log(&self, message: &str) {
        SYSCALL_STUBS.read().unwrap().sol_log(message);
    }
    fn sol_log_compute_units(&self) {
        SYSCALL_STUBS.read().unwrap().sol_log_compute_units();
    }
    fn sol_log_data(&self, fields: &[&[u8]]) {
        SYSCALL_STUBS.read().unwrap().sol_log_data(fields);
    }
    unsafe fn sol_memcmp(&self, s1: *const u8, s2: *const u8, n: usize, result: *mut i32) {
        unsafe { SYSCALL_STUBS.read().unwrap().sol_memcmp(s1, s2, n, result) };
    }
    unsafe fn sol_memcpy(&self, dst: *mut u8, src: *const u8, n: usize) {
        unsafe { SYSCALL_STUBS.read().unwrap().sol_memcpy(dst, src, n) };
    }
    unsafe fn sol_memmove(&self, dst: *mut u8, src: *const u8, n: usize) {
        unsafe { SYSCALL_STUBS.read().unwrap().sol_memmove(dst, src, n) };
    }
    unsafe fn sol_memset(&self, s: *mut u8, c: u8, n: usize) {
        unsafe { SYSCALL_STUBS.read().unwrap().sol_memset(s, c, n) };
    }
    fn sol_remaining_compute_units(&self) -> u64 {
        SYSCALL_STUBS.read().unwrap().sol_remaining_compute_units()
    }
    fn sol_set_return_data(&self, data: &[u8]) {
        SYSCALL_STUBS.read().unwrap().sol_set_return_data(data);
    }
}
