// Adapted from solana-program-entrypoint
// https://solana.com/docs/programs/faq#input-parameter-serialization

use solana_program_entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE, NON_DUP_MARKER};
use solana_pubkey::Pubkey;
use solana_sysvar::slot_history::AccountInfo;

#[allow(clippy::arithmetic_side_effects)]
#[inline(always)] // this reduces CU usage by half!
unsafe fn deserialize_account_info<'a>(
    mut offset: usize,
    new_input: *mut u8,
    original_data_len: usize,
) -> (AccountInfo<'a>, usize) {
    #[allow(clippy::cast_ptr_alignment)]
    let is_signer = *(new_input.add(offset) as *const u8) != 0;
    offset += size_of::<u8>();

    #[allow(clippy::cast_ptr_alignment)]
    let is_writable = *(new_input.add(offset) as *const u8) != 0;
    offset += size_of::<u8>();

    #[allow(clippy::cast_ptr_alignment)]
    let executable = *(new_input.add(offset) as *const u8) != 0;
    offset += size_of::<u8>();

    // padding or original_data_len
    let _original_data_len_from_new_input = *(new_input.add(offset) as *const u32);
    // TODO: Put this assert? Does pinocchio update the padding to the original data len?
    // assert!(original_data_len == _original_data_len_from_new_input as usize);
    offset += size_of::<u32>();

    let key: &Pubkey = &*(new_input.add(offset) as *const Pubkey);
    offset += size_of::<Pubkey>();

    let owner: &Pubkey = &*(new_input.add(offset) as *const Pubkey);
    offset += size_of::<Pubkey>();

    #[allow(clippy::cast_ptr_alignment)]
    let lamports = std::rc::Rc::new(std::cell::RefCell::new(
        &mut *(new_input.add(offset) as *mut u64),
    ));
    offset += size_of::<u64>();

    #[allow(clippy::cast_ptr_alignment)]
    let data_len = *(new_input.add(offset) as *const u64) as usize;
    offset += size_of::<u64>();

    let data = std::rc::Rc::new(std::cell::RefCell::new({
        std::slice::from_raw_parts_mut(new_input.add(offset), data_len)
    }));
    // use original_data_len when advancing as done at deserialize_parameters_aligned
    offset += original_data_len + MAX_PERMITTED_DATA_INCREASE;
    offset += (offset as *const u8).align_offset(BPF_ALIGN_OF_U128); // padding

    #[allow(clippy::cast_ptr_alignment)]
    let rent_epoch = *(new_input.add(offset) as *const u64);
    offset += size_of::<u64>();

    (
        AccountInfo {
            key,
            is_signer,
            is_writable,
            lamports,
            data,
            owner,
            executable,
            rent_epoch,
        },
        offset,
    )
}

#[allow(clippy::arithmetic_side_effects)]
#[inline(always)] // this reduces CU usage
unsafe fn deserialize_instruction_data<'a>(input: *mut u8, mut offset: usize) -> (&'a [u8], usize) {
    #[allow(clippy::cast_ptr_alignment)]
    let instruction_data_len = *(input.add(offset) as *const u64) as usize;
    offset += size_of::<u64>();

    let instruction_data = { std::slice::from_raw_parts(input.add(offset), instruction_data_len) };
    offset += instruction_data_len;

    (instruction_data, offset)
}

#[allow(clippy::arithmetic_side_effects)]
pub(crate) unsafe fn deserialize_updated_account_infos<'a>(
    new_input: *mut u8,
    original_data_lens: &[usize],
) -> (&'a Pubkey, Vec<AccountInfo<'a>>, &'a [u8]) {
    let mut offset: usize = 0;

    // Number of accounts present

    #[allow(clippy::cast_ptr_alignment)]
    let num_accounts = *(new_input.add(offset) as *const u64) as usize;
    offset += size_of::<u64>();

    // Account Infos

    let mut accounts = Vec::with_capacity(num_accounts);
    #[allow(clippy::needless_range_loop)]
    for i in 0..num_accounts {
        let dup_info = *(new_input.add(offset));
        offset += size_of::<u8>();
        if dup_info == NON_DUP_MARKER {
            let original_data_len = original_data_lens[i];
            let (account_info, new_offset) =
                deserialize_account_info(offset, new_input, original_data_len);
            offset = new_offset;
            accounts.push(account_info);
        } else {
            offset += 7; // padding

            // Duplicate account, clone the original
            accounts.push(accounts[dup_info as usize].clone());
        }
    }

    // Instruction data

    let (instruction_data, new_offset) = deserialize_instruction_data(new_input, offset);
    offset = new_offset;

    // Program Id

    let program_id: &Pubkey = &*(new_input.add(offset) as *const Pubkey);

    (program_id, accounts, instruction_data)
}
