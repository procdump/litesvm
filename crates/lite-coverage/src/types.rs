use solana_program::pubkey::Pubkey;
use solana_program_test::ProgramTestContext;
use std::{
    cell::RefCell,
    error::Error,
    ops::{Deref, DerefMut},
    rc::Rc,
};

pub type LiteCoverageError<T> = Result<T, Box<dyn Error + Send + Sync>>;
pub type ProgramName = String;
pub type Path = String;
pub type NativeProgram = (Pubkey, ProgramName, Path);
pub type AdditionalProgram = (Pubkey, ProgramName);

pub struct ProgramTestContextHandle {
    ctx: Option<ProgramTestContext>,
    owner: Rc<RefCell<Option<ProgramTestContext>>>,
}

impl ProgramTestContextHandle {
    pub fn new(owner: Rc<RefCell<Option<ProgramTestContext>>>) -> Self {
        // Take the context from the owner
        let ctx = owner.take();
        Self { ctx, owner }
    }
}

impl Drop for ProgramTestContextHandle {
    fn drop(&mut self) {
        // Return the context back to the owner
        *self.owner.borrow_mut() = self.ctx.take();
    }
}

impl Deref for ProgramTestContextHandle {
    type Target = Option<ProgramTestContext>;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl DerefMut for ProgramTestContextHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}
