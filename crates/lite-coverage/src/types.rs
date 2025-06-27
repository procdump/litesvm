use solana_program::pubkey::Pubkey;
use std::error::Error;

pub type LiteCoverageError<T> = Result<T, Box<dyn Error + Send + Sync>>;
pub type ProgramName = String;
pub type Path = String;
pub type NativeProgram = (Pubkey, ProgramName, Path);
pub type AdditionalProgram = (Pubkey, ProgramName);
