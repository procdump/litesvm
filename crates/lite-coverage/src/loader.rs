use crate::{
    sbf,
    stubs::{StubsManager, SyscallStubsApi, UnimplementedSyscallStubs, WrapperSyscallStubs},
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
    path::PathBuf,
    sync::{atomic::AtomicPtr, Mutex},
};

type ProgramEntrypoint = unsafe extern "C" fn(input: *mut u8) -> u64;
type ProgramSetSyscallStubsApi = unsafe extern "C" fn(stubs_api: SyscallStubsApi);

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

    let (mut parameter_bytes, _mem_region, serialized_account_meta_data) =
        solana_bpf_loader_program::serialization::serialize_parameters(
            transaction_context,
            instruction_context,
            true, // copy_account_data // There is no VM so direct mapping can not be implemented here
        )
        .map_err(|_| ProgramError::InvalidArgument)?;
    let original_data_lens: Vec<_> = serialized_account_meta_data
        .iter()
        .map(|sam| sam.original_data_len)
        .collect();

    let res = unsafe { entry(parameter_bytes.as_slice().as_ptr() as *mut _) };
    if res == 0 {
        // Deserialize data back into instruction params.
        let (_, updated_account_infos, _) = unsafe {
            sbf::deserialize_updated_account_infos(
                &mut parameter_bytes.as_slice_mut()[0] as *mut u8,
                &original_data_lens,
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
    #[cfg(target_os = "macos")]
    pub(crate) const SBF_AVATAR_EXT: &str = "dylib";
    #[cfg(target_os = "linux")]
    pub(crate) const SBF_AVATAR_EXT: &str = "so";

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
            let stubs_api = SyscallStubsApi::new();
            // Pass it to the loaded smart contract!
            self.set_syscall_stubs_api(program_id, stubs_api)?;
        }
        Ok(())
    }

    fn default_sbf_avatar_dirs() -> Vec<PathBuf> {
        let search_path = vec![
            PathBuf::from("target/debug"),
            PathBuf::from("tests/coverage_fixtures"),
        ];
        log::info!(r#"SBF avatars .so|dylib search path: {:?}"#, search_path);
        search_path
    }

    fn find_sbf_avatar_file(program_name: &str) -> Option<String> {
        for dir in Loader::default_sbf_avatar_dirs() {
            let candidate = dir.join(format!("lib{program_name}.{}", Loader::SBF_AVATAR_EXT));
            if candidate.exists() {
                let sbf_avatar_path = candidate.to_string_lossy().to_string();
                log::info!("SBF avatar found @ {}", sbf_avatar_path);
                return Some(sbf_avatar_path);
            }
        }
        None
    }

    /// Load natively a SBF avatar.
    pub(crate) fn add_program(
        &mut self,
        program_name: &str,
        program_id: &Pubkey,
    ) -> LiteCoverageError<()> {
        // Come up with the so_path of the SBF avatar based on the program_name.
        // For example: target/debug/libcounter.dylib if program_name is 'counter'.
        let sbf_avatar_path =
            Loader::find_sbf_avatar_file(program_name).ok_or(Box::<
                dyn std::error::Error + Send + Sync,
            >::from(format!(
                r#"LiteCoverage Loader: Can't find any SBF avatar for program '{program_name}'.
For example - looking for 'target/debug/libcounter.so|dylib' or
'tests/coverage_fixtures/libcounter.so|dylib' if program_name is 'counter' where
the extension .so would be on Linux or .dylib would be on MacOS. Mind that
symbolic links are also fine as with the case of using some programs built externally.
"#
            )))?;
        let lib = unsafe { Library::new(sbf_avatar_path)? };
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
