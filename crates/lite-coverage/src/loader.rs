use crate::{stubs::{StubsManager, SyscallStubsApi, UnimplementedSyscallStubs, WrapperSyscallStubs}, types::LiteCoverageError};
use libloading::{Library, Symbol};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    program_stubs::set_syscall_stubs, pubkey::Pubkey,
};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicPtr, Mutex},
};

// type ProgramCEntrypoint = unsafe extern "C" fn(input: *mut u8) -> u64;
type ProgramRustEntryPoint = unsafe extern "C" fn() -> *const ();
type ProgramSetSyscallStubsApi = unsafe extern "C" fn(stubs_api: SyscallStubsApi);

lazy_static::lazy_static! (
    pub static ref PROGRAMS_MAP: Mutex<HashMap<Pubkey, AtomicPtr<()>>> = Mutex::new(HashMap::new());
);

pub fn entrypoint<'info>(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'info>],
    data: &[u8],
) -> ProgramResult {
    let map = PROGRAMS_MAP.lock().unwrap();
    let entry = map
        .get(&*program_id)
        .unwrap()
        .load(std::sync::atomic::Ordering::Relaxed);
    let fn_ptr = entry as *const ();
    let entry: for<'a, 'b, 'info2, 'c> fn(
        &'a Pubkey,
        &'b [AccountInfo<'info2>],
        &'c [u8],
    ) -> ProgramResult = unsafe { std::mem::transmute(fn_ptr) };
    entry(program_id, accounts, data)
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
            self.set_syscall_stubs_api(&program_id, stubs_api)?;
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

        let fn_ptr = self.get_rust_entrypoint(&program_id)?;
        let mut programs_map = PROGRAMS_MAP.lock().unwrap();
        programs_map.insert(program_id.clone(), AtomicPtr::new(fn_ptr as *mut _));
        Ok(())
    }

    pub fn set_syscall_stubs_api(
        &self,
        program_id: &Pubkey,
        stubs_api: SyscallStubsApi,
    ) -> LiteCoverageError<()> {
        let func: Symbol<ProgramSetSyscallStubsApi> = unsafe {
            self.libs
                .get(program_id)
                .ok_or("No such program_id".to_string())?
                .1
                .get(b"set_stubs")?
        };
        unsafe { func(stubs_api) };
        Ok(())
    }

    fn get_rust_entrypoint(
        &self,
        program_id: &Pubkey,
    ) -> LiteCoverageError<
        for<'a, 'b, 'info, 'c> fn(
            &'a Pubkey,
            &'b [AccountInfo<'info>],
            &'c [u8],
        ) -> Result<(), ProgramError>,
    > {
        let func: Symbol<ProgramRustEntryPoint> = unsafe {
            self.libs
                .get(program_id)
                .ok_or("No such program_id".to_string())?
                .1
                .get(b"get_rust_entrypoint")?
        };
        let fn_ptr = unsafe { func() };
        let rust_fn: for<'a, 'b, 'info, 'c> fn(
            &'a Pubkey,
            &'b [AccountInfo<'info>],
            &'c [u8],
        ) -> Result<(), ProgramError> = unsafe { std::mem::transmute(fn_ptr) };
        Ok(rust_fn)
    }
}
