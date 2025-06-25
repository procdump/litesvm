use std::{
    collections::HashMap,
    sync::{atomic::AtomicPtr, Mutex},
};

use crate::stubs::{StubsManager, SyscallStubsApi, UnimplementedSyscallStubs, WrapperSyscallStubs};
use libloading::{Library, Symbol};
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;
use solana_sysvar::{program_stubs::set_syscall_stubs, slot_history::AccountInfo};

pub type CommonResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[allow(dead_code)]
type ProgramCEntrypoint = unsafe extern "C" fn(input: *mut u8) -> u64;
type ProgramRustEntryPoint = unsafe extern "C" fn() -> *const ();
type ProgramSetSyscallStubsApi = unsafe extern "C" fn(stubs_api: SyscallStubsApi);

lazy_static::lazy_static! {
    pub static ref PROGRAMS_MAP: Mutex<HashMap<Pubkey, AtomicPtr<()>>> = Mutex::new(HashMap::new());
}

pub fn entry_wrapper<'info>(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'info>],
    data: &[u8],
) -> ProgramResult {
    println!("entry_wrapper called");
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

#[derive(Debug)]
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
    pub fn adjust_stubs(&self) -> CommonResult<()> {
        println!("Adjusting stubs!");
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
            // Now create the C interface so that the smart contracts can reach our SYSCALL_STUBS!
            let stubs_api = SyscallStubsApi::new();
            // Pass it to the loaded smart contract!
            self.set_syscall_stubs_api(&program_id, stubs_api)?;
        }
        Ok(())
    }

    pub fn add(
        &mut self,
        so_path: &str,
        program_name: &str,
        program_id: &Pubkey,
    ) -> CommonResult<()> {
        let lib = unsafe { Library::new(so_path)? };
        self.libs
            .insert(*program_id, (program_name.to_string(), lib));

        let fn_ptr = self.get_rust_entrypoint(&program_id)?;
        let mut map = PROGRAMS_MAP.lock().unwrap();
        map.insert(program_id.clone(), AtomicPtr::new(fn_ptr as *mut _));
        Ok(())
    }

    pub fn set_syscall_stubs_api(
        &self,
        program_id: &Pubkey,
        stubs_api: SyscallStubsApi,
    ) -> CommonResult<()> {
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

    #[allow(dead_code)]
    pub fn get_entrypoint(
        &self,
        program_id: &Pubkey,
    ) -> CommonResult<Symbol<'_, ProgramCEntrypoint>> {
        let func: Symbol<ProgramCEntrypoint> = unsafe {
            self.libs
                .get(program_id)
                .ok_or("No such program_id".to_string())?
                .1
                .get(b"entrypoint")?
        };
        Ok(func)
    }

    pub fn get_rust_entrypoint(
        &self,
        program_id: &Pubkey,
    ) -> CommonResult<
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
