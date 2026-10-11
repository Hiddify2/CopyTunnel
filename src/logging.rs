//! Logging setup and the startup banner.
//!
//! Uses `env_logger` with a small custom format and manual ANSI colouring (the
//! 0.11 line of `env_logger` dropped the builder-style colour API, so we emit the
//! escape codes ourselves — portable and dependency-free).

use std::io::Write;

use log::{Level, LevelFilter};

fn color_code(level: Level) -> &'static str {
    match level {
        Level::Error => "\x1b[1;31m", // bold red
        Level::Warn => "\x1b[1;33m",  // bold yellow
        Level::Info => "\x1b[1;32m",  // bold green
        Level::Debug => "\x1b[1;34m", // bold blue
        Level::Trace => "\x1b[1;35m", // bold magenta
    }
}

const RESET: &str = "\x1b[0m";

/// Initialise the global logger at the given level (`trace|debug|info|warn|error`).
pub fn init(level: &str) {
    let filter = match level.to_ascii_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    let mut builder = env_logger::Builder::new();
    builder.filter_level(filter);
    builder.format(|buf, record| {
        let ts = buf.timestamp_seconds();
        writeln!(
            buf,
            "{} {}{:>5}{} {}",
            ts,
            color_code(record.level()),
            record.level(),
            RESET,
            record.args()
        )
    });
    // Ignore the error if a logger is somehow already installed.
    let _ = builder.try_init();
}

/// Print a one-time startup banner.
pub fn banner(role: &str, version: &str) {
    println!("\n  CopyTunnel v{version}  ·  role = {role}\n  encrypted layer-3 packet relay\n");
}
