use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process,
};

use serde::Serialize;

use crate::error::AppError;

/// Serializes a machine-readable value with stable pretty-printed JSON and a
/// final newline.
pub(crate) fn json<T: Serialize>(value: &T) -> Result<String, AppError> {
    serde_json::to_string_pretty(value)
        .map(|mut value| {
            value.push('\n');
            value
        })
        .map_err(|error| AppError::operational(format!("could not serialize JSON output: {error}")))
}

/// Writes output to stdout or installs it atomically at the requested path.
/// Existing paths are rejected unless `force` is explicitly set.
pub(crate) fn write(text: &str, output: Option<&Path>, force: bool) -> Result<(), AppError> {
    match output {
        None => io::stdout()
            .write_all(text.as_bytes())
            .map_err(|error| AppError::operational(format!("could not write stdout: {error}"))),
        Some(path) => atomic_install(text.as_bytes(), path, force),
    }
}

fn atomic_install(bytes: &[u8], path: &Path, force: bool) -> Result<(), AppError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        AppError::operational(format!("output path is not a file: {}", path.display()))
    })?;

    if !force {
        match fs::metadata(path) {
            Ok(_) => {
                return Err(AppError::operational(format!(
                    "output file already exists: {}; pass --force to replace it",
                    path.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(AppError::io(path, error)),
        }
    }

    let mut temporary = None;
    for attempt in 0..32_u32 {
        let candidate = temporary_path(parent, file_name, attempt);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(AppError::io(&candidate, error)),
        }
    }
    let Some((temporary, file)) = temporary else {
        return Err(AppError::operational(format!(
            "could not allocate a temporary output beside {}",
            path.display()
        )));
    };

    let result = install_temporary(&temporary, file, bytes, path, force);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn install_temporary(
    temporary: &Path,
    mut file: File,
    bytes: &[u8],
    destination: &Path,
    force: bool,
) -> Result<(), AppError> {
    file.write_all(bytes)
        .map_err(|error| AppError::io(temporary, error))?;
    file.sync_all()
        .map_err(|error| AppError::io(temporary, error))?;
    if !force && destination.exists() {
        return Err(AppError::operational(format!(
            "output file appeared before installation: {}",
            destination.display()
        )));
    }

    fs::rename(temporary, destination).map_err(|error| AppError::io(destination, error))
}

fn temporary_path(parent: &Path, file_name: &std::ffi::OsStr, attempt: u32) -> PathBuf {
    let process_id = process::id();
    let suffix = format!(".authpath-{process_id}-{attempt}.tmp");
    let mut name = file_name.to_os_string();
    name.push(suffix);
    parent.join(name)
}
