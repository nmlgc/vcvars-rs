//! This library is intended to be used as a `build-dependencies` entry in
//! `Cargo.toml`:
//!
//! ```toml
//! [build-dependencies]
//! cc = "1.0"
//! ```
//!
//! # Examples
//!

#![doc(html_root_url = "https://docs.rs/cc/1.0")]
#![cfg_attr(test, deny(warnings))]
#![deny(missing_docs)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

// These modules are all glue to support reading the MSVC version from
// the registry and from COM interfaces
#[cfg(windows)]
mod registry;
#[cfg(windows)]
#[macro_use]
mod winapi;
#[cfg(windows)]
mod com;
#[cfg(windows)]
mod setup_config;

pub mod windows_registry;

/// Configuration used to represent an invocation of a C compiler.
///
/// This can be used to figure out what compiler is in use, what the arguments
/// to it are, and what the environment variables look like for the compiler.
/// This can be used to further configure other build systems (e.g. forward
/// along CC and/or CFLAGS) or the `to_command` method can be used to run the
/// compiler itself.
#[derive(Clone, Debug)]
pub struct Tool {
    path: PathBuf,
    env: Vec<(OsString, OsString)>,
}

impl Tool {
    fn new(path: PathBuf) -> Tool {
        Tool {
            path: path,
            env: Vec::new(),
        }
    }

    /// Returns the path for this compiler.
    ///
    /// Note that this may not be a path to a file on the filesystem, e.g. "cc",
    /// but rather something which will be resolved when a process is spawned.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the set of environment variables needed for this compiler to
    /// operate.
    ///
    /// This is typically only used for MSVC compilers currently.
    pub fn env(&self) -> &[(OsString, OsString)] {
        &self.env
    }
}
