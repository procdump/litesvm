use crate::{
    sbf,
    stubs::{StubsManager, SyscallStubsApi, UnimplementedSyscallStubs, WrapperSyscallStubs},
    types::LiteCoverageError,
};
use core::str;
use libloading::{Library, Symbol};
use solana_instruction::{AccountMeta, Instruction};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    program_stubs::set_syscall_stubs, pubkey::Pubkey,
};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicPtr, Mutex},
};

type ProgramEntrypoint = unsafe extern "C" fn(input: *mut u8) -> u64;
type ProgramSetSyscallStubsApi = unsafe extern "C" fn(stubs_api: SyscallStubsApi);

lazy_static::lazy_static! (
    pub static ref PROGRAMS_MAP: Mutex<HashMap<Pubkey, AtomicPtr<()>>> = Mutex::new(HashMap::new());
);

pub fn entrypoint(program_id: &Pubkey, accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let map = PROGRAMS_MAP.lock().unwrap();
    let entry = map
        .get(program_id)
        .unwrap()
        .load(std::sync::atomic::Ordering::Relaxed);
    let fn_ptr = entry as *const ();
    let entry: ProgramEntrypoint = unsafe { std::mem::transmute(fn_ptr) };

    // Serialize entrypoint parameters with SBF ABI
    let invoke_context: &solana_program_test::InvokeContext<'_> =
        solana_program_test::get_invoke_context() as &_;
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context
        .get_current_instruction_context()
        .map_err(|_| ProgramError::InvalidArgument)?;

    let (mut parameter_bytes, _, _) =
        solana_bpf_loader_program::serialization::serialize_parameters(
            transaction_context,
            instruction_context,
            true, // copy_account_data // There is no VM so direct mapping can not be implemented here
        )
        .map_err(|_| ProgramError::InvalidArgument)?;

    // Make a copy prior to calling the entrypoint fn, we'll use it
    // for deserialization of the post-instruction updated input.
    let mut parameter_bytes_copy = parameter_bytes.clone();
    let res = unsafe { entry(parameter_bytes.as_slice().as_ptr() as *mut _) };
    if res == 0 {
        // Deserialize data back into instruction params advancing on the old input
        // while using values from the new input. The reason for this is that
        // some programs may repurpose and change the value of bytes in the old input which
        // in the end may break the canonical deserialization.
        // So try to to do our best to extract what we need while following the correct format.
        let (_, updated_account_infos, _) = unsafe {
            sbf::deserialize_updated_account_infos(
                &mut parameter_bytes_copy.as_slice_mut()[0] as *const u8,
                &mut parameter_bytes.as_slice_mut()[0] as *mut u8,
            )
        };

        let accounts_len = accounts.len();
        for i in 0..accounts_len {
            if accounts[i].lamports() != updated_account_infos[i].lamports() {
                // Lamports have changed - update.
                (**accounts[i].lamports.borrow_mut()) = updated_account_infos[i].lamports();
            }
            if *accounts[i].data.borrow() != *updated_account_infos[i].data.borrow() {
                // Account data has changed - update.
                let new_data = updated_account_infos[i].data.borrow_mut().to_vec();
                let boxed: Box<[u8]> = new_data.into_boxed_slice();
                let leaked = Box::leak(Box::new(boxed));
                *accounts[i].data.borrow_mut() = leaked;
            }

            // Account key has changed - update.
            let key_mut_ptr = accounts[i].key.as_array().as_ptr() as *mut u8;
            updated_account_infos[i]
                .key
                .as_array()
                .iter()
                .enumerate()
                .for_each(|(i, b)| {
                    unsafe { *key_mut_ptr.add(i) = *b };
                });

            // Account owner has changed - update.
            let owner_mut_ptr = accounts[i].owner.as_array().as_ptr() as *mut u8;
            updated_account_infos[i]
                .owner
                .as_array()
                .iter()
                .enumerate()
                .for_each(|(i, b)| {
                    unsafe { *owner_mut_ptr.add(i) = *b };
                });
        }

        Ok(())
    } else {
        Err(ProgramError::Custom(res as _))
    }
}

#[derive(Debug, Default)]
pub struct Loader {
    libs: HashMap<Pubkey, (String, Library)>,
}

impl Loader {
    pub fn new() -> Self {
        Self {
            libs: HashMap::new(),
        }
    }

    /// NB: This function must be called after ProgramTest .start/start_context() method!
    /// Only after starting we have the appropriate SYSCALL_STUBS initialized.
    pub fn adjust_stubs(&self) -> LiteCoverageError<()> {
        // So in ProgramTest's start() ...:
        // setup_bank() has passed and we have the appropriate stubs!
        // First to get them put there unimplemented stubs for a moment.
        let program_test_stubs = set_syscall_stubs(Box::new(UnimplementedSyscallStubs {}));
        // Store the good ones in our global variable!
        StubsManager::my_set_syscall_stubs(program_test_stubs);
        // Now create an instance so that program_test's stubs are backed with ours - the wrapper uses our global variable!
        set_syscall_stubs(Box::new(WrapperSyscallStubs {}));

        // Now for each program set the appropriate stubs
        for (program_id, _) in self.libs.iter() {
            // Now create the C interface so that the solana programs can reach our SYSCALL_STUBS!
            let stubs_api = SyscallStubsApi::new();
            // Pass it to the loaded smart contract!
            self.set_syscall_stubs_api(program_id, stubs_api)?;
        }
        Ok(())
    }

    pub fn add_program(
        &mut self,
        so_path: &str,
        program_name: &str,
        program_id: &Pubkey,
    ) -> LiteCoverageError<()> {
        let lib = unsafe { Library::new(so_path)? };
        self.libs
            .insert(*program_id, (program_name.to_string(), lib));

        let entrypoint = self.get_entrypoint(program_id)?;
        let mut programs_map = PROGRAMS_MAP.lock().unwrap();
        programs_map.insert(*program_id, AtomicPtr::new(entrypoint as *mut _));
        Ok(())
    }

    pub fn set_syscall_stubs_api(
        &self,
        program_id: &Pubkey,
        stubs_api: SyscallStubsApi,
    ) -> LiteCoverageError<()> {
        let res: Result<Symbol<ProgramSetSyscallStubsApi>, libloading::Error> = unsafe {
            self.libs
                .get(program_id)
                .ok_or("No such program_id".to_string())?
                .1
                .get(b"set_stubs")
        };
        match res {
            Ok(func) => unsafe { func(stubs_api) },
            Err(e) => {
                // REVISIT: The idea behind is this to try working with stubs
                // and if not neccesary (as is the case with pinocchio as it
                // seems for now) to continue
                println!("Can't set stubs, error: {}! Go on", e);
            }
        }
        Ok(())
    }

    fn get_entrypoint(&self, program_id: &Pubkey) -> LiteCoverageError<ProgramEntrypoint> {
        let entrypoint: Symbol<ProgramEntrypoint> = unsafe {
            self.libs
                .get(program_id)
                .ok_or("No such program_id".to_string())?
                .1
                .get(b"entrypoint")?
        };
        Ok(*entrypoint)
    }
}

// REVISIT: pinocchio's syscalls impls are here for now
#[no_mangle]
pub extern "C" fn sol_log_(msg: *const u8, len: u64) {
    let message = unsafe { std::slice::from_raw_parts(msg, len as _) };
    let m = String::from_utf8_lossy(message);
    crate::stubs::SYSCALL_STUBS.read().unwrap().sol_log(&m);
}

#[no_mangle]
pub extern "C" fn sol_log_compute_units_() {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_log_compute_units();
}

#[no_mangle]
pub extern "C" fn sol_remaining_compute_units() -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_remaining_compute_units()
}

#[no_mangle]
pub extern "C" fn sol_memcpy_(dst: *mut u8, src: *const u8, n: u64) {
    unsafe {
        crate::stubs::SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_memcpy(dst, src, n as _);
    }
}

#[no_mangle]
pub extern "C" fn sol_memmove_(dst: *mut u8, src: *const u8, n: u64) {
    unsafe {
        crate::stubs::SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_memmove(dst, src, n as _);
    }
}

#[no_mangle]
pub extern "C" fn sol_memcmp_(s1: *const u8, s2: *const u8, n: u64, result: *mut i32) {
    unsafe {
        crate::stubs::SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_memcmp(s1, s2, n as _, result);
    }
}

#[no_mangle]
pub extern "C" fn sol_memset_(s: *mut u8, c: u8, n: u64) {
    unsafe {
        crate::stubs::SYSCALL_STUBS
            .read()
            .unwrap()
            .sol_memset(s, c, n as _);
    }
}

#[no_mangle]
pub extern "C" fn sol_get_stack_height() -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_stack_height()
}

#[no_mangle]
pub extern "C" fn sol_get_clock_sysvar(addr: *mut u8) -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_clock_sysvar(addr)
}

#[no_mangle]
pub extern "C" fn sol_get_epoch_schedule_sysvar(addr: *mut u8) -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_epoch_schedule_sysvar(addr)
}

#[no_mangle]
pub extern "C" fn sol_get_fees_sysvar(addr: *mut u8) -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_fees_sysvar(addr)
}

#[no_mangle]
pub extern "C" fn sol_get_rent_sysvar(addr: *mut u8) -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_rent_sysvar(addr)
}

#[no_mangle]
pub extern "C" fn sol_get_epoch_rewards_sysvar(addr: *mut u8) -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_epoch_rewards_sysvar(addr)
}

#[no_mangle]
pub extern "C" fn sol_get_last_restart_slot(addr: *mut u8) -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_last_restart_slot(addr)
}

#[no_mangle]
pub extern "C" fn sol_get_epoch_stake(vote_address: *const u8) -> u64 {
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_epoch_stake(vote_address)
}

#[no_mangle]
pub extern "C" fn sol_get_sysvar(
    sysvar_id_addr: *const u8,
    result: *mut u8,
    offset: u64,
    length: u64,
) -> u64 {
    crate::stubs::SYSCALL_STUBS.read().unwrap().sol_get_sysvar(
        sysvar_id_addr,
        result,
        offset,
        length,
    )
}

#[no_mangle]
pub extern "C" fn sol_set_return_data(data: *const u8, length: u64) {
    let slice = unsafe { std::slice::from_raw_parts(data, length as _) };
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_set_return_data(slice);
}

pub const PUBKEY_BYTES: usize = 32;
pub type CPubkey = [u8; PUBKEY_BYTES];

#[no_mangle]
pub extern "C" fn sol_get_return_data(data: *mut u8, length: u64, program_id: *mut CPubkey) -> u64 {
    let ret_data = crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_return_data();

    match ret_data {
        None => 0,
        Some((key, src)) => {
            // Caller is wondering how many to allocate.
            if length == 0 {
                unsafe { *program_id = *key.as_array() };
                return src.len() as _;
            }

            // Caller is ready with the allocation - we're expected to copy the data.
            // Let's check if there's enough space.
            let src_len = src.len() as _;
            if src_len > length || unsafe { *program_id } != *key.as_array() {
                return 0;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr(), data, length as _);
            };
            src_len
        }
    }
}

#[no_mangle]
pub extern "C" fn sol_log_data(data: *const u8, data_len: u64) {
    // reinterpret the buffer as a fat pointer to (*const u8, usize) pairs
    let fat_ptrs = data as *const (*const u8, u64);
    let mut v: Vec<&[u8]> = Vec::with_capacity(data_len as _);
    for i in 0..data_len {
        let (data_ptr, len) = unsafe { *fat_ptrs.add(i as _) };
        let slice = unsafe { std::slice::from_raw_parts(data_ptr, len as _) };
        v.push(slice);
    }
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_log_data(&v[..]);
}

#[repr(C)]
pub struct CProcessedSiblingInstruction {
    pub data_len: u64,
    pub accounts_len: u64,
}

#[repr(C)]
#[derive(Clone)]
pub struct CAccountMeta {
    pub pubkey: *const CPubkey,
    pub is_writable: bool,
    pub is_signer: bool,
}

impl Default for CAccountMeta {
    fn default() -> Self {
        Self {
            pubkey: &[0u8; 32],
            is_writable: false,
            is_signer: false,
        }
    }
}

#[no_mangle]
pub extern "C" fn sol_get_processed_sibling_instruction(
    index: u64,
    meta: *mut CProcessedSiblingInstruction,
    program_id: *mut CPubkey,
    data: *mut u8,
    accounts: *mut CAccountMeta,
) -> u64 {
    let instruction = crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_get_processed_sibling_instruction(index as _);
    match instruction {
        None => 0, // 0 - No processed sibling instruction.
        Some(instr) => {
            let data_len = instr.data.len();
            let accounts_len = instr.accounts.len();
            unsafe {
                if (*meta).accounts_len == 0 && (*meta).data_len == 0 {
                    // Caller is wondering how many to allocate.
                    // https://github.com/anza-xyz/solana-sdk/blob/master/instruction/src/syscalls.rs#L32
                    (*meta).data_len = data_len as _;
                    (*meta).accounts_len = accounts_len as _;
                    *program_id = *instr.program_id.as_array();

                    // 1 - Return the allocation details so that caller can prepare.
                    return 1;
                }
            }

            // Caller is ready with the allocation.
            // But first - a little sanity check.
            unsafe {
                if (*meta).data_len != data_len as u64
                    || (*meta).accounts_len != accounts_len as u64
                    || *program_id != *instr.program_id.as_array()
                {
                    return 0;
                }

                // Now just copy the data and the account metas.
                std::ptr::copy_nonoverlapping(instr.data.as_ptr(), data, data_len);
                // Now copy the account metas taking into consideration that pubkey is a *const u8.
                // https://github.com/anza-xyz/pinocchio/blob/main/sdk/pinocchio/src/instruction.rs#L116
                for i in 0..instr.accounts.len() {
                    let account_meta = accounts.add(i);
                    (*account_meta).is_signer = instr.accounts[i].is_signer;
                    (*account_meta).is_writable = instr.accounts[i].is_writable;
                    (*account_meta).pubkey = Box::leak(Box::new(instr.accounts[i].pubkey))
                        as *const _ as *const [u8; 32];
                }
            }
            2 // 2 - All good.
        }
    }
}

#[repr(C)]
pub struct CAccountInfo {
    // Public key of the account.
    key: *const CPubkey,

    // Number of lamports owned by this account.
    lamports: *const u64,

    // Length of data in bytes.
    data_len: u64,

    // On-chain data within this account.
    data: *const u8,

    // Program that owns this account.
    owner: *const CPubkey,

    // The epoch at which this account will next owe rent.
    rent_epoch: u64,

    // Transaction was signed by this account's key?
    is_signer: bool,

    // Is the account writable?
    is_writable: bool,

    // This account's data contains a loaded program (and is now read-only).
    executable: bool,
}

#[repr(C)]
struct CInstruction {
    /// Public key of the program.
    program_id: *const CPubkey,

    /// Accounts expected by the program instruction.
    accounts: *const CAccountMeta,

    /// Number of accounts expected by the program instruction.
    accounts_len: u64,

    /// Data expected by the program instruction.
    data: *const u8,

    /// Length of the data expected by the program instruction.
    data_len: u64,
}

#[no_mangle]
pub extern "C" fn sol_invoke_signed_c(
    instruction_addr: *const u8,
    account_infos_addr: *const u8,
    account_infos_len: u64,
    signers_seeds_addr: *const u8,
    signers_seeds_len: u64,
) -> u64 {
    // instruction
    let cinstr = instruction_addr as *const CInstruction;
    let instruction = unsafe {
        Instruction {
            program_id: Pubkey::new_from_array(*(*cinstr).program_id),
            accounts: {
                (0..(*cinstr).accounts_len)
                    .map(|i| {
                        let cam = (*cinstr).accounts.add(i as _);
                        AccountMeta {
                            pubkey: Pubkey::new_from_array(*(*cam).pubkey),
                            is_signer: (*cam).is_signer,
                            is_writable: (*cam).is_writable,
                        }
                    })
                    .collect()
            },
            data: {
                let slice = std::slice::from_raw_parts((*cinstr).data, (*cinstr).data_len as _);
                slice.to_vec()
            },
        }
    };

    // account_infos
    let ai_fat_ptr = account_infos_addr as *const (*const CAccountInfo, u64);
    let mut account_infos: Vec<AccountInfo<'_>> = vec![];
    for i in 0..account_infos_len {
        let (cai, _) = unsafe { *ai_fat_ptr.add(i as _) };
        let ai = unsafe {
            AccountInfo {
                key: &*((*cai).key as *const Pubkey),
                lamports: std::rc::Rc::new(std::cell::RefCell::new(
                    &mut *((*cai).lamports as *mut _),
                )),
                data: {
                    let slice =
                        std::slice::from_raw_parts_mut((*cai).data as _, (*cai).data_len as _);
                    std::rc::Rc::new(std::cell::RefCell::new(slice))
                },
                owner: &*((*cai).owner as *const Pubkey),
                rent_epoch: (*cai).rent_epoch,
                is_signer: (*cai).is_signer,
                is_writable: (*cai).is_writable,
                executable: (*cai).executable,
            }
        };
        account_infos.push(ai);
    }

    // signers_seeds
    let q_fat_ptr = signers_seeds_addr as *const (*const u8, u64);
    let mut qv: Vec<Vec<&[u8]>> = vec![];
    for q in 0..signers_seeds_len {
        let (q_data_ptr, q_data_len) = unsafe { *q_fat_ptr.add(q as _) };
        let mut pv: Vec<&[u8]> = vec![];
        for p in 0..q_data_len {
            let p_fat_ptr = q_data_ptr as *const (*const u8, u64);
            let (p_data_ptr, p_data_len) = unsafe { *p_fat_ptr.add(p as _) };
            let slice = unsafe { std::slice::from_raw_parts(p_data_ptr, p_data_len as usize) };
            pv.push(slice);
        }
        qv.push(pv);
    }

    let signers_seeds: Vec<_> = qv.iter().map(|e| &e[..]).collect();
    match crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_invoke_signed(&instruction, &account_infos[..], &signers_seeds[..])
    {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sol_log_pubkey(pubkey: *const u8) {
    let pubkey = unsafe { &*(pubkey as *const Pubkey) };
    crate::stubs::SYSCALL_STUBS
        .read()
        .unwrap()
        .sol_log(&pubkey.to_string());
}

#[repr(C)]
pub struct SyscallStubsApi2 {
    pub sol_log_: extern "C" fn(message: *const u8, len: u64),
    pub sol_log_compute_units_: extern "C" fn(),
    pub sol_remaining_compute_units: extern "C" fn() -> u64,
    pub sol_invoke_signed_c: extern "C" fn(
        instruction_addr: *const u8,
        account_infos_addr: *const u8,
        account_infos_len: u64,
        signers_seeds_addr: *const u8,
        signers_seeds_len: u64,
    ) -> u64,
    pub sol_get_clock_sysvar: extern "C" fn(addr: *mut u8) -> u64,
    pub sol_get_epoch_schedule_sysvar: extern "C" fn(addr: *mut u8) -> u64,
    pub sol_get_fees_sysvar: extern "C" fn(addr: *mut u8) -> u64,
    pub sol_get_rent_sysvar: extern "C" fn(addr: *mut u8) -> u64,
    pub sol_get_last_restart_slot: extern "C" fn(addr: *mut u8) -> u64,
    pub sol_get_sysvar:
        extern "C" fn(sysvar_id_addr: *const u8, result: *mut u8, offset: u64, length: u64) -> u64,
    pub sol_memcpy_: extern "C" fn(dst: *mut u8, src: *const u8, n: u64),
    pub sol_memmove_: extern "C" fn(dst: *mut u8, src: *const u8, n: u64),
    pub sol_memcmp_: extern "C" fn(s1: *const u8, s2: *const u8, n: u64, result: *mut i32),
    pub sol_memset_: extern "C" fn(s: *mut u8, c: u8, n: u64),
    pub sol_get_return_data:
        extern "C" fn(data: *mut u8, length: u64, program_id: *mut CPubkey) -> u64,
    pub sol_set_return_data: extern "C" fn(data: *const u8, length: u64),
    pub sol_log_data: extern "C" fn(data: *const u8, data_len: u64),
    pub sol_get_processed_sibling_instruction: extern "C" fn(
        index: u64,
        meta: *mut CProcessedSiblingInstruction,
        program_id: *mut CPubkey,
        data: *mut u8,
        accounts: *mut CAccountMeta,
    ) -> u64,
    pub sol_get_stack_height: extern "C" fn() -> u64,
    pub sol_get_epoch_rewards_sysvar: extern "C" fn(addr: *mut u8) -> u64,
    pub sol_get_epoch_stake: extern "C" fn(vote_address: *const u8) -> u64,
}

impl SyscallStubsApi2 {
    pub fn new() -> Self {
        Self {
            sol_get_clock_sysvar,
            sol_get_epoch_rewards_sysvar,
            sol_get_epoch_schedule_sysvar,
            sol_get_fees_sysvar,
            sol_get_last_restart_slot,
            sol_get_rent_sysvar,
            sol_get_stack_height,
            sol_log_,
            sol_log_compute_units_,
            sol_memcmp_,
            sol_memcpy_,
            sol_memmove_,
            sol_memset_,
            sol_remaining_compute_units,
            sol_get_return_data,
            sol_set_return_data,
            sol_log_data,
            sol_invoke_signed_c,
            sol_get_processed_sibling_instruction,
            sol_get_epoch_stake,
            sol_get_sysvar,
        }
    }
}

#[repr(C)]
pub struct SolAppSyscallStubs2 {
    pub stubs_api2: SyscallStubsApi2,
}

impl solana_sysvar::program_stubs::SyscallStubs for SolAppSyscallStubs2 {
    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api2.sol_get_clock_sysvar)(var_addr)
    }
    fn sol_get_epoch_rewards_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api2.sol_get_epoch_rewards_sysvar)(var_addr)
    }
    fn sol_get_epoch_schedule_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api2.sol_get_epoch_schedule_sysvar)(var_addr)
    }
    fn sol_get_epoch_stake(&self, vote_address: *const u8) -> u64 {
        (self.stubs_api2.sol_get_epoch_stake)(vote_address)
    }
    fn sol_get_fees_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api2.sol_get_fees_sysvar)(var_addr)
    }
    fn sol_get_last_restart_slot(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api2.sol_get_last_restart_slot)(var_addr)
    }
    fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api2.sol_get_rent_sysvar)(var_addr)
    }
    fn sol_get_stack_height(&self) -> u64 {
        (self.stubs_api2.sol_get_stack_height)()
    }
    fn sol_remaining_compute_units(&self) -> u64 {
        (self.stubs_api2.sol_remaining_compute_units)()
    }
    unsafe fn sol_memcmp(&self, s1: *const u8, s2: *const u8, n: usize, result: *mut i32) {
        (self.stubs_api2.sol_memcmp_)(s1, s2, n as u64, result);
    }
    unsafe fn sol_memcpy(&self, dst: *mut u8, src: *const u8, n: usize) {
        (self.stubs_api2.sol_memcpy_)(dst, src, n as u64)
    }
    unsafe fn sol_memmove(&self, dst: *mut u8, src: *const u8, n: usize) {
        (self.stubs_api2.sol_memmove_)(dst, src, n as u64)
    }
    unsafe fn sol_memset(&self, s: *mut u8, c: u8, n: usize) {
        (self.stubs_api2.sol_memset_)(s, c, n as u64)
    }
    fn sol_get_sysvar(
        &self,
        sysvar_id_addr: *const u8,
        var_addr: *mut u8,
        offset: u64,
        length: u64,
    ) -> u64 {
        (self.stubs_api2.sol_get_sysvar)(sysvar_id_addr, var_addr, offset, length)
    }
    fn sol_log_compute_units(&self) {
        (self.stubs_api2.sol_log_compute_units_)()
    }
    fn sol_log(&self, message: &str) {
        (self.stubs_api2.sol_log_)(message.as_ptr(), message.len() as u64)
    }
    fn sol_log_data(&self, fields: &[&[u8]]) {
        (self.stubs_api2.sol_log_data)(fields.as_ptr() as *const u8, fields.len() as u64);
    }
    fn sol_set_return_data(&self, data: &[u8]) {
        (self.stubs_api2.sol_set_return_data)(data.as_ptr(), data.len() as u64);
    }
    fn sol_get_return_data(&self) -> Option<(Pubkey, Vec<u8>)> {
        let mut program_id = [0u8; 32];
        let data_bytes_to_alloc =
            (self.stubs_api2.sol_get_return_data)(&mut u8::default(), 0, &mut program_id);
        if data_bytes_to_alloc == 0 {
            return None;
        }
        let mut vdata = vec![0u8; data_bytes_to_alloc as usize];
        let same_bytes_num_expected = (self.stubs_api2.sol_get_return_data)(
            vdata.as_mut_ptr(),
            vdata.len() as _,
            &mut program_id,
        );
        if same_bytes_num_expected == data_bytes_to_alloc {
            Some((Pubkey::new_from_array(program_id), vdata))
        } else {
            None
        }
    }
    fn sol_get_processed_sibling_instruction(&self, index: usize) -> Option<Instruction> {
        let mut meta = CProcessedSiblingInstruction {
            accounts_len: 0,
            data_len: 0,
        };
        let mut program_id = [0u8; 32];
        if 1 == (self.stubs_api2.sol_get_processed_sibling_instruction)(
            index as _,
            &mut meta,
            &mut program_id,
            &mut u8::default(),
            &mut CAccountMeta::default(),
        ) {
            let accounts_to_alloc = meta.accounts_len;
            let data_bytes_to_alloc = meta.data_len;
            let mut caccount_metas = vec![CAccountMeta::default(); accounts_to_alloc as _];
            let mut vdata = vec![0u8; data_bytes_to_alloc as _];
            let res = (self.stubs_api2.sol_get_processed_sibling_instruction)(
                index as _,
                &mut meta,
                &mut program_id,
                vdata.as_mut_ptr(),
                caccount_metas.as_mut_ptr(),
            );
            if res != 0 && res != 1 {
                let mut account_metas = vec![];
                for cai in &caccount_metas {
                    let pubkey = unsafe { *Box::from_raw(cai.pubkey as *mut _) };
                    let account_meta = AccountMeta {
                        is_signer: cai.is_signer,
                        is_writable: cai.is_writable,
                        pubkey: Pubkey::new_from_array(pubkey),
                    };
                    account_metas.push(account_meta);
                }
                return Some(Instruction {
                    accounts: account_metas,
                    data: vdata,
                    program_id: program_id.into(),
                });
            }
        }
        None
    }
    fn sol_invoke_signed(
        &self,
        instruction: &Instruction,
        account_infos: &[AccountInfo],
        signers_seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        let mut caccounts = vec![];
        for account_meta in &instruction.accounts {
            let caccount = CAccountMeta {
                is_signer: account_meta.is_signer,
                is_writable: account_meta.is_writable,
                pubkey: &account_meta.pubkey as *const _ as *const CPubkey,
            };
            caccounts.push(caccount);
        }
        let cinstr = CInstruction {
            program_id: &instruction.program_id as *const _ as *const CPubkey,
            accounts_len: instruction.accounts.len() as _,
            data_len: instruction.data.len() as _,
            accounts: caccounts.as_ptr(),
            data: instruction.data.as_ptr(),
        };
        let mut caccount_infos = vec![];
        for account_info in account_infos {
            let caccount_info = CAccountInfo {
                is_signer: account_info.is_signer,
                is_writable: account_info.is_writable,
                executable: account_info.executable,
                rent_epoch: account_info.rent_epoch,
                data_len: account_info.data_len() as _,
                data: account_info.data.borrow().as_ptr(),
                lamports: *account_info.lamports.borrow(),
                key: account_info.key as *const _ as *const CPubkey,
                owner: account_info.owner as *const _ as *const CPubkey,
            };
            caccount_infos.push(caccount_info);
        }
        let res = (self.stubs_api2.sol_invoke_signed_c)(
            &cinstr as *const _ as *const u8,
            caccount_infos.as_ptr() as *const u8,
            caccount_infos.len() as _,
            signers_seeds.as_ptr() as *const u8,
            signers_seeds.len() as _,
        );
        if res == 0 {
            Ok(())
        } else {
            Err(ProgramError::Custom(res as _))
        }
    }
}
// REVISIT
