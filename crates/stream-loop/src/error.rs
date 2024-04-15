use thiserror::Error;

pub type StreamResult<T> = Result<T, StreamError>;

#[derive(Error, Debug)]
pub enum StreamError {
	#[error("io error: {0}")]
	Io(#[from] std::io::Error),
	#[error("invalid hash between copy")]
	InvalidHash,
}
