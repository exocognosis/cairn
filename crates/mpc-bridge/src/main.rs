//! `cairn-mpc-worker`: the reference three-party backend as a standalone process.

use std::path::PathBuf;
use std::time::Duration;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dir) = args
        .iter()
        .position(|a| a == "--socket-dir")
        .and_then(|i| args.get(i + 1))
    else {
        eprintln!("usage: cairn-mpc-worker --socket-dir <dir>\n\nReference worker: clear-text, NOT a secure computation.");
        return std::process::ExitCode::from(2);
    };
    match mpc_bridge::serve(&PathBuf::from(dir), Duration::from_secs(30)) {
        Ok(worker) => {
            eprintln!("cairn-mpc-worker: reference backend (clear text, not MPC) on {dir}/p{{1,2,3}}.sock");
            worker.join();
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("cairn-mpc-worker: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
