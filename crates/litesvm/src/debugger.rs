use {
    crate::{register_tracing::compute_hash, InvocationInspectCallback, LiteSVM},
    solana_program_runtime::invoke_context::InvokeContext,
    solana_transaction::sanitized::SanitizedTransaction,
    solana_transaction_context::IndexOfAccount,
    std::{fs::File, io::Write},
};

const DEFAULT_PATH: &str = "target/sbf/trace";

pub struct DefaultDebuggerCallback {
    pub sbf_trace_dir: String,
}

impl DefaultDebuggerCallback {
    pub fn handler(
        &self,
        svm: &LiteSVM,
        tx: &SanitizedTransaction,
        _program_indices: &[IndexOfAccount],
        _invoke_context: &InvokeContext,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_dir = std::env::current_dir()?;
        let sbf_trace_dir = current_dir.join(&self.sbf_trace_dir);
        std::fs::create_dir_all(&sbf_trace_dir)?;

        let base_fname = sbf_trace_dir.join("debug_session");
        let mut debug_session_file = File::create(base_fname.with_extension("log"))?;

        tx.message().account_keys().iter().for_each(|pubkey| {
            if let Ok(elf_data) = svm.accounts_db().try_program_elf_bytes(pubkey) {
                let _ = debug_session_file
                    .write(format!("{}={}", pubkey, compute_hash(elf_data)).as_bytes());
            }
        });

        Ok(())
    }
}

impl Default for DefaultDebuggerCallback {
    fn default() -> Self {
        Self {
            // User can override default path with `SBF_TRACE_DIR` environment variable.
            sbf_trace_dir: std::env::var("SBF_TRACE_DIR").unwrap_or(DEFAULT_PATH.to_string()),
        }
    }
}

impl InvocationInspectCallback for DefaultDebuggerCallback {
    fn before_invocation(
        &self,
        svm: &LiteSVM,
        tx: &SanitizedTransaction,
        program_indices: &[IndexOfAccount],
        invoke_context: &InvokeContext,
    ) {
        let _ = self.handler(svm, tx, program_indices, invoke_context);
    }

    fn after_invocation(
        &self,
        _svm: &LiteSVM,
        _invoke_context: &InvokeContext,
        _register_tracing_enabled: bool,
    ) {
    }
}
