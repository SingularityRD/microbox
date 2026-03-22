use crate::args::ValidateArgs;
use crate::runner::{prepare_context, select_backend_for_policy};

pub fn run(args: ValidateArgs) -> Result<i32, microbox_core::SandboxError> {
    let context = prepare_context(&args.policy)?;
    let crate::runner::RunContext { policy, .. } = context;
    let backend = select_backend_for_policy(args.policy.backend)?;
    let capabilities = backend.capabilities();

    println!("MicroBox validate");
    println!("backend = {}", capabilities.name);
    println!(
        "secure_enforcement = {}",
        if capabilities.secure_enforcement {
            "yes"
        } else {
            "no"
        }
    );
    for line in policy.summary_lines() {
        println!("{}", line);
    }
    if !capabilities.notes.is_empty() {
        println!("notes:");
        for note in capabilities.notes {
            println!("  - {}", note);
        }
    }

    Ok(0)
}
