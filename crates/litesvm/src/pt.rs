use std::{cell::RefCell, error::Error, sync::Arc};

use solana_account::ReadableAccount;
use solana_program_test::{
    processor, set_invoke_context, InvokeContext, ProgramTest, ProgramTestContext,
};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use tokio::runtime::Runtime;

use crate::{
    accounts_db::AccountsDb,
    loader::{self, Loader},
};
pub type PtError<T> = Result<T, Box<dyn Error + Send + Sync>>;
pub type ProgramName = String;
pub type Path = String;
pub type NativeProgram = (Pubkey, ProgramName, Path);

#[derive(Clone)]
pub struct Pt {
    pub programs: Vec<NativeProgram>,
    pub pt_context: Arc<RefCell<ProgramTestContext>>,
    rt: Arc<Box<Runtime>>,
}

impl Pt {
    pub fn new(programs: Vec<NativeProgram>) -> PtError<Self> {
        let static_programs = Box::leak(Box::new(programs.clone()));
        let mut pt_native = ProgramTest::default();
        pt_native.prefer_bpf(false);

        let mut loader = Loader::new();
        for (program_id, program_name, so_path) in static_programs.iter() {
            println!(
                "Adding native program {} with id: {}",
                program_name, program_id
            );
            loader.add(&so_path, &program_name, &program_id)?;
            pt_native.add_program(program_name, *program_id, processor!(loader::entry_wrapper));
        }
        println!("Loaded: {:?}", loader);

        let rt = tokio::runtime::Runtime::new()?;
        let pt_context = rt.block_on(async move {
            let pt_context = pt_native.start_with_context().await;
            pt_context
        });
        loader.adjust_stubs()?;
        Ok(Self {
            pt_context: Arc::new(RefCell::new(pt_context)),
            programs,
            rt: Arc::new(Box::new(rt)),
        })
    }

    pub fn send_transaction(
        &self,
        mut invoke_context: &mut InvokeContext,
        tx: VersionedTransaction,
        accounts_db: AccountsDb,
    ) -> PtError<()> {
        set_invoke_context(&mut invoke_context);
        let _: PtError<()> = self.rt.block_on(async {
            for (account_address, account) in &accounts_db.inner {
                // println!("Account: {:#?} data: {:#?}", account_address, account);
                let to_add = self
                    .programs
                    .iter()
                    .find(|(id, _, _)| id == account.owner())
                    .is_some();
                if to_add == true {
                    self.pt_context
                        .borrow_mut()
                        .set_account(account_address, account);
                }
            }
            let recent_blockhash = self
                .pt_context
                .borrow()
                .banks_client
                .get_latest_blockhash()
                .await?;

            println!("PREPARING TRANS: {:#?}", tx);
            let mut trans = tx
                .clone()
                .into_legacy_transaction()
                .ok_or("Can't convert to legacy tx".to_string())?;
            let payer = &self.pt_context.borrow().payer;
            println!("TRANS PAYER: {}", payer.pubkey());
            trans.message.recent_blockhash = recent_blockhash;
            trans.message.account_keys[0] = payer.pubkey().clone();
            trans.sign(&[&payer], recent_blockhash);
            let versioned_tx = VersionedTransaction::from(trans);
            println!("TRANS AFTER SIGN: {:#?}", versioned_tx);

            let res = self
                .pt_context
                .borrow()
                .banks_client
                .process_transaction(versioned_tx)
                .await;
            println!("OUR TX RES: {:?}", res);
            Ok(())
        });
        Ok(())
    }
}
