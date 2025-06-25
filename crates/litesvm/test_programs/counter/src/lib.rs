use borsh::{BorshDeserialize, BorshSerialize};
use {
    solana_account_info::{next_account_info, AccountInfo},
    solana_msg::msg,
    solana_program_error::{ProgramError, ProgramResult},
    solana_pubkey::{declare_id, Pubkey},
    solana_clock::Clock,
    solana_sysvar::Sysvar,
};

mod state;
use state::Counter;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[cfg(not(feature = "no-entrypoint"))]
use solana_program_entrypoint::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (instruction_discriminant, instruction_data_inner) = instruction_data.split_at(1);
    msg!("accounts: {:#?}, instdata: {:#?}", accounts, instruction_data);
    match instruction_discriminant[0] {
        0 => {
            let got_clock = Clock::get()?;
            msg!("Clock timestamp: {:?}", got_clock);
            msg!("Instruction: Increment");
            process_increment_counter(accounts, instruction_data_inner)?;
        }
        _ => {
            msg!("Error: unknown instruction")
        }
    }
    Ok(())
}

pub fn process_increment_counter(
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> Result<(), ProgramError> {
    let account_info_iter = &mut accounts.iter();

    let counter_account = next_account_info(account_info_iter)?;
    assert!(
        counter_account.is_writable,
        "Counter account must be writable"
    );
    let mut counter = Counter::try_from_slice(&counter_account.try_borrow_data()?)?;
    counter.count += 1;
    counter.serialize(&mut *counter_account.data.borrow_mut())?;

    msg!("Counter state incremented to {:?}", counter.count);
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn get_rust_entrypoint() -> *const () {
    println!("get_rust_entrypoint() in counter!");
    process_instruction as *const ()
}

#[repr(C)]
pub struct CInstruction {
    pub program_id: [u8; 32],
    pub accounts_ptr: *const solana_program::instruction::AccountMeta,
    pub accounts_len: usize,
    pub data_ptr: *const u8,
    pub data_len: usize,
}

impl CInstruction {
    pub fn from(instr: &solana_program::instruction::Instruction) -> Self {
        CInstruction {
            program_id: instr.program_id.to_bytes(),
            accounts_ptr: instr.accounts.as_ptr(),
            accounts_len: instr.accounts.len(),
            data_ptr: instr.data.as_ptr(),
            data_len: instr.data.len(),
        }
    }

    pub fn to_instruction(
        cinstr: &CInstruction,
    ) -> solana_program::instruction::Instruction {
        let accounts: Vec<solana_program::instruction::AccountMeta> = Vec::from(unsafe {
            std::slice::from_raw_parts(cinstr.accounts_ptr as *mut _, cinstr.accounts_len)
        });
        let data = Vec::from(unsafe {
            std::slice::from_raw_parts(cinstr.data_ptr as *mut _, cinstr.data_len)
        });
        solana_program::instruction::Instruction {
            program_id: Pubkey::new_from_array(cinstr.program_id),
            accounts,
            data,
        }
    }
}

#[repr(C)]
pub struct CBytes {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct CBytesArray {
    pub ptr: *const CBytes,
    pub len: usize,
}

#[repr(C)]
pub struct CBytesArrayArray {
    pub ptr: *const CBytesArray,
    pub len: usize,
}

impl CBytesArrayArray {
    pub fn from(input: &[&[&[u8]]]) -> CBytesArrayArray {
        let mut outer = Vec::new();
        let mut all_cbytes = Vec::new(); // To hold all CBytes flat

        for inner in input {
            let mut inner_cbytes = Vec::new();
            for slice in *inner {
                inner_cbytes.push(CBytes {
                    ptr: slice.as_ptr(),
                    len: slice.len(),
                });
            }

            let inner_ptr = inner_cbytes.as_ptr();
            all_cbytes.push(inner_cbytes); // store to keep memory alive

            outer.push(CBytesArray {
                ptr: inner_ptr,
                len: inner.len(),
            });
        }

        let outer_ptr = outer.as_ptr();
        // TODO: LEAK IT TO PRESERVE IT! FIX
        // ensure memory lives
        outer.leak();
        all_cbytes.leak();

        CBytesArrayArray {
            ptr: outer_ptr,
            len: input.len(),
        }
    }

    pub fn to_array_array_array(c: &CBytesArrayArray) -> Vec<Vec<&[u8]>> {
        let mut result = Vec::new();
        for i in 0..c.len {
            let c_inner = unsafe { &*c.ptr.add(i) };
            let mut inner = Vec::new();

            for j in 0..c_inner.len {
                let c_bytes = unsafe { &*c_inner.ptr.add(j) };
                let slice = unsafe { std::slice::from_raw_parts(c_bytes.ptr, c_bytes.len) };
                inner.push(slice);
            }

            result.push(inner);
        }
        result
    }

    pub fn convert<'a>(input: &'a Vec<Vec<&'a [u8]>>) -> Vec<&'a [&'a [u8]]> {
        input.iter().map(|inner| inner.as_slice()).collect()
    }
}

#[repr(C)]
pub struct CAccountInfoSlice {
    pub ptr: *const CAccountInfo,
    pub len: usize,
}

#[repr(C)]
pub struct CAccountInfo {
    pub key: *const u8, // [u8; 32]
    pub lamports: *mut u64,
    pub data: *mut u8,
    pub data_len: usize,
    pub owner: *const u8, // [u8; 32]
    pub rent_epoch: u64,
    pub is_signer: bool,
    pub is_writable: bool,
    pub executable: bool,
}

impl CAccountInfoSlice {
    fn to_c_account_info_slice<'a, 'b>(ais: &'a [AccountInfo<'b>]) -> CAccountInfoSlice {
        let mut c_infos = Vec::with_capacity(ais.len());

        for ai in ais {
            let lamports_ref = &mut *ai.lamports.borrow_mut();
            let data_ref = &mut *ai.data.borrow_mut();

            c_infos.push(CAccountInfo {
                key: ai.key.as_ref().as_ptr(),
                lamports: *lamports_ref as *mut u64,
                data: data_ref.as_mut_ptr(),
                data_len: data_ref.len(),
                owner: ai.owner.as_ref().as_ptr(),
                rent_epoch: ai.rent_epoch,
                is_signer: ai.is_signer,
                is_writable: ai.is_writable,
                executable: ai.executable,
            });
        }

        let slice = CAccountInfoSlice {
            ptr: c_infos.as_ptr(),
            len: c_infos.len(),
        };

        // TODO: Fix - leak to preserve it.
        c_infos.leak();
        slice
    }

    pub fn reconstruct_account_infos(slice: &CAccountInfoSlice) -> Vec<AccountInfo<'static>> {
        let mut result = Vec::with_capacity(slice.len);

        unsafe {
            for i in 0..slice.len {
                let cai = &*slice.ptr.add(i);

                let lamports = std::rc::Rc::new(std::cell::RefCell::new(&mut *cai.lamports));
                let data = std::rc::Rc::new(std::cell::RefCell::new(
                    std::slice::from_raw_parts_mut(cai.data, cai.data_len),
                ));

                result.push(AccountInfo {
                    key: &*(cai.key as *const Pubkey),
                    lamports,
                    data,
                    owner: &*(cai.owner as *const Pubkey),
                    rent_epoch: cai.rent_epoch,
                    is_signer: cai.is_signer,
                    is_writable: cai.is_writable,
                    executable: cai.executable,
                });
            }
        }

        result
    }
}

#[repr(C)]
pub struct SyscallStubsApi {
    pub sol_log: extern "C" fn(msg_ptr: *const u8, len: usize),
    pub sol_log_compute_units: extern "C" fn(),
    pub sol_remaining_compute_units: extern "C" fn() -> u64,
    pub sol_invoke_signed: extern "C" fn(
        instruction: CInstruction,
        account_infos: *mut CAccountInfoSlice,
        signers_seeds: CBytesArrayArray,
    ) -> i64,
    pub sol_get_clock_sysvar: extern "C" fn(var_addr: *mut u8) -> u64,
    pub sol_get_epoch_schedule_sysvar: extern "C" fn(var_addr: *mut u8) -> u64,
    pub sol_get_fees_sysvar: extern "C" fn(var_addr: *mut u8) -> u64,
    pub sol_get_rent_sysvar: extern "C" fn(var_addr: *mut u8) -> u64,
    pub sol_get_last_restart_slot: extern "C" fn(var_addr: *mut u8) -> u64,
    pub sol_memcpy: extern "C" fn(dst: *mut u8, src: *const u8, n: usize),
    pub sol_memmove: extern "C" fn(dst: *mut u8, src: *const u8, n: usize),
    pub sol_memcmp: extern "C" fn(s1: *const u8, s2: *const u8, n: usize, result: *mut i32),
    pub sol_memset: extern "C" fn(s: *mut u8, c: u8, n: usize),
    // pub sol_get_return_data: extern "C" fn() -> Option<(Pubkey, Vec<u8>)>,
    pub sol_set_return_data: extern "C" fn(data_ptr: *const u8, len: usize),
    // pub sol_log_data: extern "C" fn(data: &[&[u8]]),
    // pub sol_get_processed_sibling_instruction: extern "C" fn(index: usize) -> Option<Instruction>,
    pub sol_get_stack_height: extern "C" fn() -> u64,
    pub sol_get_epoch_rewards_sysvar: extern "C" fn(var_addr: *mut u8) -> u64,
}

#[repr(C)]
pub struct MySyscallStubs {
    pub stubs_api: SyscallStubsApi,
}

#[cfg(not(target_os = "solana"))]
impl solana_program::program_stubs::SyscallStubs for MySyscallStubs {
    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        println!("sol_get_clock_sysvar called");
        let res = (self.stubs_api.sol_get_clock_sysvar)(var_addr);
        println!("after sol_get_clock_sysvar");
        res
    }
    fn sol_get_epoch_rewards_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api.sol_get_epoch_rewards_sysvar)(var_addr)
    }
    fn sol_get_epoch_schedule_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api.sol_get_epoch_schedule_sysvar)(var_addr)
    }
    fn sol_get_fees_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api.sol_get_fees_sysvar)(var_addr)
    }
    fn sol_get_last_restart_slot(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api.sol_get_last_restart_slot)(var_addr)
    }
    fn sol_get_processed_sibling_instruction(
        &self,
        _index: usize,
    ) -> Option<solana_program::instruction::Instruction> {
        println!("sol_get_processed_sibling_instruction called!");
        unimplemented!()
    }
    fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
        (self.stubs_api.sol_get_rent_sysvar)(var_addr)
    }
    fn sol_get_return_data(&self) -> Option<(Pubkey, Vec<u8>)> {
        println!("sol_get_return_data called!");
        unimplemented!()
    }
    fn sol_get_stack_height(&self) -> u64 {
        (self.stubs_api.sol_get_stack_height)()
    }
    fn sol_invoke_signed(
        &self,
        instruction: &solana_program::instruction::Instruction,
        account_infos: &[AccountInfo],
        signers_seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        println!("sol_invoke_signed called!");
        println!("FAV: instruction {:#?}", instruction);
        println!("FAV: signers: {:#?}", signers_seeds);
        println!("FAV: account_infos: {:#?}", account_infos);
        // // TEST
        // for ai in account_infos.iter() {
        //     Box::leak(Box::new(Rc::clone(&ai.lamports)));
        //     Box::leak(Box::new(Rc::clone(&ai.data)));
        // }
        // // TEST
        let cinstr = CInstruction::from(&instruction);
        let caccountinfos =
            &mut CAccountInfoSlice::to_c_account_info_slice(&account_infos) as *mut _;
        let cbytesarrayarray = CBytesArrayArray::from(&signers_seeds);
        for ai in account_infos.iter() {
            println!("FAV BEFORE ai: {} -> lamports: {}", ai.key, ai.lamports());
            println!("FAV BEFORE ai: {} -> data.len: {}", ai.key, ai.data_len());
            println!(
                "FAV BEFORE ai: {} -> data.ptr: {:p}",
                ai.key,
                ai.data.as_ptr()
            );
        }
        (self.stubs_api.sol_invoke_signed)(cinstr, caccountinfos, cbytesarrayarray);
        for (i, ai) in account_infos.iter().enumerate() {
            println!("FAV AFTER ai: {} -> lamports: {}", ai.key, ai.lamports());
            println!("FAV AFTER ai: {} -> data.len: {}", ai.key, ai.data_len());
            println!(
                "FAV AFTER ai: {} -> data.ptr: {:p}",
                ai.key,
                ai.data.as_ptr()
            );

            // After the transaction the data might have changed, so update it.
            // We expect that the remote has updated it accordingly.
            let cai: *mut CAccountInfo = unsafe { (*caccountinfos).ptr.add(i) } as *mut _;
            let data_ptr = (*ai.data.borrow_mut()).as_mut_ptr();
            let data_len = unsafe { (*cai).data_len };
            let new_slice = unsafe { std::slice::from_raw_parts_mut(data_ptr, data_len) };
            println!(
                "Data's len has changed to new_slice.len(): {}",
                new_slice.len()
            );
            (*ai.data.borrow_mut()) = new_slice;
        }
        println!("DONE!");
        Ok(())
    }
    fn sol_log(&self, message: &str) {
        let len = message.len();
        let msg_ptr = message.as_ptr();
        (self.stubs_api.sol_log)(msg_ptr, len);
    }
    fn sol_log_compute_units(&self) {
        (self.stubs_api.sol_log_compute_units)();
    }
    fn sol_log_data(&self, _fields: &[&[u8]]) {
        println!("sol_log_data called!");
        unimplemented!()
    }
    unsafe fn sol_memcmp(&self, s1: *const u8, s2: *const u8, n: usize, result: *mut i32) {
        (self.stubs_api.sol_memcmp)(s1, s2, n, result);
    }
    unsafe fn sol_memcpy(&self, dst: *mut u8, src: *const u8, n: usize) {
        (self.stubs_api.sol_memcpy)(dst, src, n);
    }
    unsafe fn sol_memmove(&self, dst: *mut u8, src: *const u8, n: usize) {
        (self.stubs_api.sol_memmove)(dst, src, n);
    }
    unsafe fn sol_memset(&self, s: *mut u8, c: u8, n: usize) {
        (self.stubs_api.sol_memset)(s, c, n);
    }
    fn sol_remaining_compute_units(&self) -> u64 {
        (self.stubs_api.sol_remaining_compute_units)()
    }
    fn sol_set_return_data(&self, data: &[u8]) {
        let len = data.len();
        let data_ptr = data.as_ptr();
        (self.stubs_api.sol_set_return_data)(data_ptr, len);
    }
}

#[cfg(not(target_os = "solana"))]
#[no_mangle]
pub extern "C" fn set_stubs(stubs_api: SyscallStubsApi) {
    println!("Calling set_stubs in counter!");
    let stubs = Box::new(MySyscallStubs { stubs_api });
    let _ = solana_program::program_stubs::set_syscall_stubs(stubs);
    // let _ = solana_program::program_stubs::set_syscall_stubs(Box::new(
    //     solana_program_test::SyscallStubs {},
    // ));
}