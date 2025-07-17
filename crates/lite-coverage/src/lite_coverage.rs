use std::{io::Write, rc::Rc};

use solana_keypair::Keypair;

use crate::{
    loader::{entrypoint, Loader},
    types::{LiteCoverageError, NativeProgram},
    AdditionalProgram, ProgramTestContextHandle,
};
use {
    solana_account::AccountSharedData,
    solana_program::pubkey::Pubkey,
    solana_program_test::{processor, ProgramTest, ProgramTestContext},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    std::{cell::RefCell, sync::Arc},
    tokio::runtime::Runtime,
};

/// Main object to look after code coverage.
#[derive(Clone)]
pub struct LiteCoverage {
    pub programs: Vec<NativeProgram>,
    pub pt_context: Rc<RefCell<Option<ProgramTestContext>>>,
    rt: Arc<Runtime>,
}

impl LiteCoverage {
    /// Get an instance to the main code coverage object.
    pub fn new(
        programs: Vec<NativeProgram>,
        additional_programs: Vec<AdditionalProgram>,
        payer: Keypair,
    ) -> LiteCoverageError<Self> {
        let static_programs = Box::leak(Box::new(programs.clone()));
        let mut program_test = ProgramTest::default();
        program_test.prefer_bpf(false);
        program_test.set_payer(payer);

        for (pubkey, name) in additional_programs.clone().into_iter() {
            let name = Box::leak(Box::new(name));
            program_test.add_upgradeable_program_to_genesis(name, &pubkey);
        }

        let mut loader = Loader::new();
        for (program_id, program_name, so_path) in static_programs.iter() {
            log::info!(
                "Adding native program {} with program id: {}",
                program_name,
                program_id
            );
            loader.add_program(so_path, program_name, program_id)?;
            program_test.add_program(program_name, *program_id, processor!(entrypoint));
        }
        log::info!("Loaded: {:?}", loader);

        let rt = tokio::runtime::Runtime::new()?;
        let pt_context = rt.block_on(async move { program_test.start_with_context().await });
        loader.adjust_stubs()?;

        LiteCoverage::log_anchor_test_event_artifacts(programs.clone(), additional_programs)?;

        Ok(Self {
            pt_context: Rc::new(RefCell::new(Some(pt_context))),
            programs,
            rt: Arc::new(rt),
        })
    }

    /// Get a handle to the ProgramTestContext.
    pub fn get_program_test_context(&self) -> ProgramTestContextHandle {
        assert!(
            self.pt_context.borrow().is_some(),
            "ProgramTestContext is already acquired!"
        );
        ProgramTestContextHandle::new(Rc::clone(&self.pt_context))
    }

    /// Add an account to the ProgramTestContext.
    pub fn add_account(&self, account_pubkey: &Pubkey, account_data: &AccountSharedData) {
        let mut pt_context = self.get_program_test_context();
        if let Some(ctx) = &mut *pt_context {
            ctx.set_account(account_pubkey, account_data);
        }
    }

    /// Sign with our payer while also using our latest blockhash.
    async fn re_sign_tx(
        &self,
        tx: &VersionedTransaction,
    ) -> LiteCoverageError<VersionedTransaction> {
        // TODO tx must be resigned for all signers
        let pt_context = self.get_program_test_context();
        let ctx = pt_context
            .as_ref()
            .ok_or(Box::<dyn std::error::Error + Send + Sync>::from(
                "Missing ProgramTestContext",
            ))?;
        let payer = ctx.payer.insecure_clone();
        let recent_blockhash = ctx.banks_client.get_latest_blockhash().await?;

        let mut trans = tx.clone().into_legacy_transaction().unwrap();
        trans.message.recent_blockhash = recent_blockhash;
        trans.message.account_keys[0] = payer.pubkey();
        trans.sign(&[&payer], recent_blockhash);
        Ok(VersionedTransaction::from(trans))
    }

    /// Send the transaction to the natively loaded SBF avatars already prepared for
    /// obtaining code coverage.
    pub fn send_transaction(
        &self,
        tx: VersionedTransaction,
        accounts: &[(Pubkey, AccountSharedData)],
    ) -> LiteCoverageError<()> {
        let _: LiteCoverageError<()> = self.rt.block_on(async {
            for (account_pubkey, account_data) in accounts {
                self.add_account(account_pubkey, account_data);
            }
            let re_signed_tx = self.re_sign_tx(&tx).await?;

            let pt_context = self.get_program_test_context();
            let ctx =
                pt_context
                    .as_ref()
                    .ok_or(Box::<dyn std::error::Error + Send + Sync>::from(
                        "Missing ProgramTestContext",
                    ))?;
            let res = ctx
                .banks_client
                .process_transaction_with_metadata(re_signed_tx)
                .await?;

            log::info!("LiteCoverage transaction result: {:#?}", res);
            Ok(())
        });
        Ok(())
    }

    /// Log some events provided that some anchor envvars are globally set.
    /// This is useful for anchor to know that it's litesvm that's actually used.
    /// With this information anchor can go further visualizing the code coverage results
    /// or bail out.
    fn log_anchor_test_event_artifacts(
        progs: Vec<NativeProgram>,
        additional_progs: Vec<AdditionalProgram>,
    ) -> LiteCoverageError<()> {
        if let Ok(report_events) = std::env::var("ANCHOR_TEST_CODE_COVERAGE_REPORT_EVENTS") {
            if report_events == "true" {
                if let Ok(event_file) =
                    std::env::var("ANCHOR_TEST_CODE_COVERAGE_ARTIFACTS_EVENT_FILE")
                {
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .write(true)
                        .open(format!("{}.{}.log", event_file, std::process::id()))?;
                    file.write_all("litesvm=true\n".as_bytes())?;
                    for (pubkey, name, path) in &progs {
                        file.write_all(format!("{}={},{}\n", name, pubkey, path).as_bytes())?;
                    }
                    for (pubkey, name) in &additional_progs {
                        file.write_all(format!("{}={}\n", name, pubkey).as_bytes())?;
                    }
                }
            }
        }
        Ok(())
    }
}
