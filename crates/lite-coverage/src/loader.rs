use crate::{
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
    sync::{atomic::AtomicPtr, Mutex},
};

type ProgramEntrypoint = unsafe extern "C" fn(input: *mut u8) -> u64;
type ProgramSetSyscallStubsApi = unsafe extern "C" fn(stubs_api: SyscallStubsApi);

lazy_static::lazy_static! (
    pub static ref PROGRAMS_MAP: Mutex<HashMap<Pubkey, AtomicPtr<()>>> = Mutex::new(HashMap::new());
);

pub fn entrypoint<'info>(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'info>],
    _data: &[u8],
) -> ProgramResult {
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

    let ix_input_before = parameter_bytes.as_slice().to_vec();
    let res = unsafe { entry(parameter_bytes.as_slice().as_ptr() as *mut _) };
    if ix_input_before != parameter_bytes.as_slice() {
        // Deserialize data back into instruction params
        let (_, updated_account_infos, _) = unsafe {
            solana_program_entrypoint::deserialize(
                &mut parameter_bytes.as_slice_mut()[0] as *mut u8,
            )
        };

        // println!(
        //     "DIFFERENT inputs, is data different: {}",
        //     data != updated_data
        // );
        // Persist the changes
        println!(
            "accounts.len(): {}, updated_account_infos.len(): {}",
            accounts.len(),
            updated_account_infos.len()
        );
        let _ = std::fs::write(
            "/tmp/new_accounts.txt",
            format!("{:#?}", updated_account_infos),
        );
        // #[allow(clippy::transmute_ptr_to_ptr)]
        // #[allow(mutable_transmutes)]
        // let accounts = unsafe { std::mem::transmute::<&[AccountInfo<'info>], &mut [AccountInfo<'info>]>(accounts) };
        let len = accounts.len();
        for i in 0..len {
            (**accounts[i].lamports.borrow_mut()) = updated_account_infos[i].lamports();
            let new_data = updated_account_infos[i].data.borrow_mut().to_vec();
            let boxed: Box<[u8]> = new_data.into_boxed_slice();
            let leaked = Box::leak(Box::new(boxed));
            *accounts[i].data.borrow_mut() = leaked;

            // unsafe {
            //     (*accounts)[i].is_signer = updated_account_infos[i].is_signer;
            //     (*accounts)[i].is_writable = updated_account_infos[i].is_writable;
            //     (*accounts)[i].executable = updated_account_infos[i].executable;
            //     (*accounts)[i].rent_epoch = updated_account_infos[i].rent_epoch;
            // }
            #[allow(clippy::transmute_ptr_to_ptr)]
            #[allow(mutable_transmutes)]
            let account_info_mut =
                unsafe { std::mem::transmute::<&Pubkey, &mut Pubkey>(accounts[i].key) };
            *account_info_mut = *updated_account_infos[i].key;
            #[allow(clippy::transmute_ptr_to_ptr)]
            #[allow(mutable_transmutes)]
            let account_info_mut =
                unsafe { std::mem::transmute::<&Pubkey, &mut Pubkey>(accounts[i].owner) };
            *account_info_mut = *updated_account_infos[i].owner;
            // #[allow(clippy::transmute_ptr_to_ptr)]
            // #[allow(mutable_transmutes)]
            // let account_info_mut =
            //     unsafe { std::mem::transmute::<&u64, &mut u64>(&accounts[i].rent_epoch) };
            // *account_info_mut = updated_account_infos[i].rent_epoch;
            // #[allow(clippy::transmute_ptr_to_ptr)]
            // #[allow(mutable_transmutes)]
            // let account_info_mut =
            //     unsafe { std::mem::transmute::<&bool, &mut bool>(&accounts[i].is_signer) };
            // *account_info_mut = updated_account_infos[i].is_signer;
            // #[allow(clippy::transmute_ptr_to_ptr)]
            // #[allow(mutable_transmutes)]
            // let account_info_mut =
            //     unsafe { std::mem::transmute::<&bool, &mut bool>(&accounts[i].is_writable) };
            // *account_info_mut = updated_account_infos[i].is_writable;
            // #[allow(clippy::transmute_ptr_to_ptr)]
            // #[allow(mutable_transmutes)]
            // let account_info_mut =
            //     unsafe { std::mem::transmute::<&bool, &mut bool>(&accounts[i].executable) };
            // *account_info_mut = updated_account_infos[i].executable;
        }
        // for (dst, src) in accounts.iter().zip(updated_account_infos.iter()) {
        //     println!("account {} updated: {}", dst.key, src.key);

        //     **dst.lamports.borrow_mut() = src.lamports();
        //     {
        //         let src_data = src.data.borrow_mut();
        //         let mut dst_data = dst.data.borrow_mut();
        //         println!("NEW LEN: {}, OLD LEN: {}", src_data.len(), dst_data.len());

        //         let _ = std::mem::replace(&mut dst_data, src_data);
        //     }
        // }

        // let _ = std::fs::write("/tmp/old_accounts.txt", format!("{:#02x?}", accounts));
        // let _ = std::fs::write("/tmp/old_data.txt", format!("{:#02x?}", data));
        // let _ = std::fs::write("/tmp/new_data.txt", format!("{:#02x?}", _updated_data));
        // panic!("STOP");
        // // if data != updated_data {
        // //     let mut_ref_data: &mut [u8] = unsafe { std::mem::transmute(data) };
        // // }
    }

    if res == 0 {
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

// REVISIT: pinocchio's single syscall impl for now
#[no_mangle]
pub extern "C" fn sol_log_(msg: *const u8, len: u64) {
    let message = unsafe { std::slice::from_raw_parts(msg, len as _) };
    let m = str::from_utf8(&message).unwrap();
    crate::stubs::SYSCALL_STUBS.read().unwrap().sol_log(&m);
}

#[no_mangle]
pub extern "C" fn sol_log_pubkey(_pubkey: *const u8) {
    println!("Unimplemented sol_log_pubkey syscall!");
}
// REVISIT
