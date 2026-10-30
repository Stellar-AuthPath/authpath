use std::{fmt, path::Path};

pub(crate) const EXIT_SUCCESS: i32 = 0;
pub(crate) const EXIT_FINDING: i32 = 10;
pub(crate) const EXIT_INCONCLUSIVE: i32 = 20;
pub(crate) const EXIT_INVALID_INPUT: i32 = 2;
pub(crate) const EXIT_OPERATIONAL: i32 = 3;

#[derive(Debug)]
pub(crate) enum AppError {
    InvalidInput(String),
    Operational(String),
}

impl AppError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }

    pub(crate) fn operational(message: impl Into<String>) -> Self {
        Self::Operational(message.into())
    }

    pub(crate) fn io(path: &Path, error: impl fmt::Display) -> Self {
        Self::Operational(format!("{}: {error}", path.display()))
    }

    pub(crate) const fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidInput(_) => EXIT_INVALID_INPUT,
            Self::Operational(_) => EXIT_OPERATIONAL,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "invalid input: {message}"),
            Self::Operational(message) => write!(formatter, "operational error: {message}"),
        }
    }
}

impl std::error::Error for AppError {}
