use {
    crate::{error, InvocationInspectCallback, LiteSVM},
    sha2::{Digest, Sha256},
    solana_address::Address,
    solana_program_runtime::{
        invoke_context::{Executable, InvokeContext, RegisterTrace},
        solana_sbpf::static_analysis::RegisterTraceEntry,
    },
    solana_transaction::sanitized::SanitizedTransaction,
    solana_transaction_context::{IndexOfAccount, InstructionContext},
    std::{
        fs::File,
        io::Write,
        sync::{Arc, Mutex},
    },
};

const DEFAULT_PATH: &str = "target/sbf/trace";

use solana_program_runtime::solana_sbpf::vm::TraceEvent;

pub type TraceEventCallback = dyn Fn(InstructionContext, &Executable, TraceEvent) + Send + Sync;
pub type CollectedData = (Address, Vec<u8>, Vec<RegisterTraceEntry>);

pub struct DefaultRegisterTracingCallback {
    pub sbf_trace_dir: String,
    pub trace_event_callback: Option<Arc<TraceEventCallback>>,
    pub register_traces: Arc<Mutex<Vec<CollectedData>>>,
}

impl Default for DefaultRegisterTracingCallback {
    fn default() -> Self {
        let sbf_trace_dir = std::env::var("SBF_TRACE_DIR").unwrap_or(DEFAULT_PATH.to_string());
        let mut instance = Self {
            // User can override default path with `SBF_TRACE_DIR` environment variable.
            sbf_trace_dir: sbf_trace_dir.clone(),
            trace_event_callback: None,
            register_traces: Arc::new(Mutex::new(Vec::default())),
        };
        instance.trace_event_callback = Some(Arc::new({
            let register_traces = Arc::clone(&instance.register_traces);
            move |instruction_context, executable, trace_event| match trace_event {
                TraceEvent::InvokingDebugger(_debug_port) => {
                    let persist_program_id = || -> Result<(), Box<dyn std::error::Error>> {
                        let program_id = instruction_context.get_program_key()?;
                        let current_dir = std::env::current_dir()?;
                        let sbf_trace_dir = current_dir.join(sbf_trace_dir.clone());
                        std::fs::create_dir_all(&sbf_trace_dir)?;
                        let base_fname = sbf_trace_dir.join("debugging_session");
                        let mut program_id_file =
                            File::create(base_fname.with_extension("program_id"))?;
                        program_id_file.write(program_id.to_string().as_bytes())?;
                        Ok(())
                    };

                    if let Err(e) = persist_program_id() {
                        error!("debugger: failed to write program_id: {}", e);
                    }
                }
                TraceEvent::RegisterTrace(register_trace) => {
                    let program_id = instruction_context.get_program_key().unwrap();
                    let text_bytes = executable.get_text_bytes().1.to_vec();
                    register_traces.lock().unwrap().push((
                        *program_id,
                        text_bytes,
                        register_trace.to_vec(),
                    ));
                }
            }
        }));
        instance
    }
}

impl DefaultRegisterTracingCallback {
    pub fn get_trace_event_callback(&self) -> Option<&Arc<TraceEventCallback>> {
        self.trace_event_callback.as_ref()
    }

    pub fn handler(
        &self,
        svm: &LiteSVM,
        program_id: &Address,
        text_bytes: &[u8],
        register_trace: RegisterTrace,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if register_trace.is_empty() {
            // Can't do much with an empty trace.
            return Ok(());
        }

        let current_dir = std::env::current_dir()?;
        let sbf_trace_dir = current_dir.join(&self.sbf_trace_dir);
        std::fs::create_dir_all(&sbf_trace_dir)?;

        let trace_digest = compute_hash(as_bytes(register_trace));
        let base_fname = sbf_trace_dir.join(&trace_digest[..16]);
        let mut regs_file = File::create(base_fname.with_extension("regs"))?;
        let mut insns_file = File::create(base_fname.with_extension("insns"))?;
        let mut program_id_file = File::create(base_fname.with_extension("program_id"))?;

        // Persist the program id.
        let _ = program_id_file.write(program_id.to_string().as_bytes());

        if let Ok(elf_data) = svm.accounts_db().try_program_elf_bytes(program_id) {
            // Persist the preload hash of the executable.
            let mut so_hash_file = File::create(base_fname.with_extension("exec.sha256"))?;
            let _ = so_hash_file.write(compute_hash(elf_data).as_bytes());
        }

        // Get the relocated executable.
        let program = text_bytes;
        for regs in register_trace.iter() {
            // The program counter is stored in r11.
            let pc = regs[11];
            // From the executable fetch the instruction this program counter points to.
            let insn =
                solana_program_runtime::solana_sbpf::ebpf::get_insn_unchecked(program, pc as usize)
                    .to_array();

            // Persist them in files.
            let _ = regs_file.write(as_bytes(regs.as_slice()))?;
            let _ = insns_file.write(insn.as_slice())?;
        }

        Ok(())
    }
}

impl InvocationInspectCallback for DefaultRegisterTracingCallback {
    fn before_invocation(
        &self,
        svm: &LiteSVM,
        tx: &SanitizedTransaction,
        _: &[IndexOfAccount],
        _: &InvokeContext,
    ) {
        let persist_program_accounts_sha256 = || -> Result<(), Box<dyn std::error::Error>> {
            let current_dir = std::env::current_dir()?;
            let sbf_trace_dir = current_dir.join(&self.sbf_trace_dir);
            std::fs::create_dir_all(&sbf_trace_dir)?;

            let base_fname = sbf_trace_dir.join("debugging_session");
            let mut debug_session_file = File::create(base_fname.with_extension("elfs_sha256"))?;

            tx.message().account_keys().iter().for_each(|pubkey| {
                if let Ok(elf_data) = svm.accounts_db().try_program_elf_bytes(pubkey) {
                    let _ = debug_session_file
                        .write(format!("{}={}", pubkey, compute_hash(elf_data)).as_bytes());
                }
            });
            Ok(())
        };

        if let Err(e) = persist_program_accounts_sha256() {
            error!(
                "debugger: failed to persist SHA-256 of program accounts' elf data: {}",
                e
            );
        }
    }

    fn after_invocation(&self, svm: &LiteSVM, _: &InvokeContext, register_tracing_enabled: bool) {
        if register_tracing_enabled {
            let register_traces = std::mem::take(&mut *self.register_traces.lock().unwrap());
            // Only read the register traces if they were actually enabled.
            for (program_id, text_bytes, register_trace) in register_traces {
                if let Err(e) = self.handler(
                    svm,
                    &program_id,
                    text_bytes.as_slice(),
                    register_trace.as_slice(),
                ) {
                    eprintln!("Error collecting the register tracing: {}", e);
                }
            }
        }
    }

    fn get_trace_event_callback(&self) -> Option<&Arc<TraceEventCallback>> {
        self.trace_event_callback.as_ref()
    }
}

pub(crate) fn as_bytes<T>(slice: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const u8, std::mem::size_of_val(slice)) }
}

fn compute_hash(slice: &[u8]) -> String {
    hex::encode(Sha256::digest(slice).as_slice())
}
