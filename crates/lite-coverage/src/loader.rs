use crate::{
    sbf,
    stubs::{StubsManager, SyscallStubsApi2, UnimplementedSyscallStubs, WrapperSyscallStubs},
    types::LiteCoverageError,
};
use core::str;
use libloading::{Library, Symbol};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    program_stubs::set_syscall_stubs, pubkey::Pubkey,
};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicPtr, Mutex},
};

type ProgramEntrypoint = unsafe extern "C" fn(input: *mut u8) -> u64;
type ProgramSetSyscallStubsApi = unsafe extern "C" fn(stubs_api: SyscallStubsApi2);

lazy_static::lazy_static! (
    pub static ref PROGRAMS_MAP: Mutex<HashMap<Pubkey, AtomicPtr<()>>> = Mutex::new(HashMap::new());
);

/// ProgramTest invokes this entrypoint to dispatch to the right entrypoint
/// of the natively loaded SBF avatars.
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

/// A loader object to track loaded SBF avatars.
#[derive(Debug, Default)]
pub(crate) struct Loader {
    libs: HashMap<Pubkey, (String, Library)>,
}

impl Loader {
    // Get an instance to a loader.
    pub(crate) fn new() -> Self {
        Self {
            libs: HashMap::new(),
        }
    }

    /// Adjust stubs for the natively loaded SBF avatars.
    /// NB: This function must be called after ProgramTest .start/start_context() method!
    /// Only after starting we have the appropriate SYSCALL_STUBS initialized.
    pub(crate) fn adjust_stubs(&self) -> LiteCoverageError<()> {
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
            let stubs_api = SyscallStubsApi2::new();
            // Pass it to the loaded smart contract!
            self.set_syscall_stubs_api(program_id, stubs_api)?;
        }
        Ok(())
    }

    /// Load natively a SBF avatar.
    pub(crate) fn add_program(
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

    /// Set stubs at the natively loaded SBF avatar.
    pub(crate) fn set_syscall_stubs_api(
        &self,
        program_id: &Pubkey,
        stubs_api: SyscallStubsApi2,
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
                log::warn!("Can't set stubs, error: {}! Proceed forward..", e);
            }
        }
        Ok(())
    }

    /// Obtain the entrypoint for this program_id.
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
