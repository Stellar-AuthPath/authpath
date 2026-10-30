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
    drop(file);

    if force {
        return fs::rename(temporary, destination)
            .map_err(|error| AppError::io(destination, error));
    }

    install_synced_temporary(temporary, destination)
}

/// Installs a fully written temporary file without replacing an existing path.
///
/// `hard_link` creates the destination directory entry atomically and fails
/// with `AlreadyExists` if another process wins the destination race. The
/// temporary link is then removed, leaving the destination as the sole link.
/// There is deliberately no rename fallback: a fallback could replace a
/// destination created after any existence check.
fn install_synced_temporary(temporary: &Path, destination: &Path) -> Result<(), AppError> {
    match fs::hard_link(temporary, destination) {
        Ok(()) => fs::remove_file(temporary).map_err(|error| {
            AppError::operational(format!(
                "output installed at {} but temporary cleanup failed for {}: {error}",
                destination.display(),
                temporary.display()
            ))
        }),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Err(AppError::operational(format!(
                "output file already exists or was created concurrently: {}; pass --force to replace it",
                destination.display()
            )))
        }
        Err(error) => Err(AppError::operational(format!(
            "atomic no-replace output installation is unsupported for {}: {error}",
            destination.display()
        ))),
    }
}

fn temporary_path(parent: &Path, file_name: &std::ffi::OsStr, attempt: u32) -> PathBuf {
    let process_id = process::id();
    let suffix = format!(".authpath-{process_id}-{attempt}.tmp");
    let mut name = file_name.to_os_string();
    name.push(suffix);
    parent.join(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("authpath-output-test-{}-{sequence}", process::id()));
            fs::create_dir_all(&path).expect("create output test directory");
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temporary_file(directory: &TestDirectory, name: &str) -> (PathBuf, File) {
        let path = directory.file(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create temporary output");
        (path, file)
    }

    fn temporary_entries(directory: &TestDirectory) -> Vec<PathBuf> {
        fs::read_dir(&directory.0)
            .expect("read output test directory")
            .map(|entry| entry.expect("read output entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".authpath-"))
            })
            .collect()
    }

    #[test]
    fn no_replace_preserves_existing_destination() {
        let directory = TestDirectory::new();
        let destination = directory.file("existing.json");
        fs::write(&destination, b"old").expect("write existing destination");

        let error = atomic_install(b"new", &destination, false).unwrap_err();

        assert!(format!("{error}").contains("already exists or was created concurrently"));
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        assert!(temporary_entries(&directory).is_empty());
    }

    #[test]
    fn no_replace_rejects_destination_created_before_atomic_install() {
        let directory = TestDirectory::new();
        let destination = directory.file("competing.json");
        let (temporary, mut file) = temporary_file(&directory, ".authpath-competing.tmp");
        file.write_all(b"new").expect("write temporary output");
        file.sync_all().expect("sync temporary output");
        drop(file);

        // This models another process creating the destination after the
        // temporary output was prepared but before no-replace installation.
        fs::write(&destination, b"competitor").expect("create competing destination");
        let error = install_synced_temporary(&temporary, &destination).unwrap_err();

        assert!(format!("{error}").contains("already exists or was created concurrently"));
        assert_eq!(fs::read(&destination).unwrap(), b"competitor");
        assert!(temporary.exists());
    }

    #[test]
    fn failed_force_install_cleans_temporary_output() {
        let directory = TestDirectory::new();
        let destination = directory.file("destination-directory");
        fs::create_dir(&destination).expect("create destination directory");

        let error = atomic_install(b"new", &destination, true).unwrap_err();

        assert!(format!("{error}").contains("destination-directory"));
        assert!(destination.is_dir());
        assert!(temporary_entries(&directory).is_empty());
    }
}
