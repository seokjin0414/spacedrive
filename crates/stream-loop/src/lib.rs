#![warn(
	clippy::all,
	clippy::pedantic,
	clippy::correctness,
	clippy::perf,
	clippy::style,
	clippy::suspicious,
	clippy::complexity,
	clippy::nursery,
	clippy::unwrap_used,
	unused_qualifications,
	rust_2018_idioms,
	clippy::expect_used,
	trivial_casts,
	trivial_numeric_casts,
	unused_allocation,
	clippy::as_conversions,
	clippy::dbg_macro,
	clippy::deprecated_cfg_attr,
	clippy::separated_literal_suffix,
	deprecated
)]
#![forbid(unsafe_code, deprecated_in_future)]
#![allow(
	clippy::missing_errors_doc,
	clippy::module_name_repetitions,
	clippy::similar_names
)]

mod error;
pub use error::{StreamError, StreamResult};

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub const BLOCK_SIZE: usize = 1_024_576; // 1MiB, good balance between performance and memory usage

pub struct StreamWriter<RW>
where
	RW: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
	source: RW,
	dest: RW,
	length: usize,
}

enum ProgressUpdate {
	Percentage(usize),
}

impl<RW> StreamWriter<RW>
where
	RW: AsyncReadExt + AsyncWriteExt + AsyncSeekExt + Unpin + Send,
{
	pub const fn new(source: RW, dest: RW, length: usize) -> Self {
		Self {
			source,
			dest,
			length,
		}
	}

	pub async fn stream_move_with_percentage(mut self) -> StreamResult<()> {
		let total_blocks = self.length / BLOCK_SIZE;

		let mut buf = vec![0u8; BLOCK_SIZE].into_boxed_slice();
		let mut hasher_src = blake3::Hasher::new();
		let mut counter = 0;

		loop {
			let count = self.source.read(&mut buf).await?;
			self.dest.write_all(&buf[..count]).await?;
			hasher_src.update(&buf[..count]);

			counter += 1;
			// emit total_blocks / counter

			if count != BLOCK_SIZE {
				// emit 100%
				break;
			}
		}

		self.dest.flush().await?;

		let mut hasher_dest = blake3::Hasher::new();

		loop {
			let count = self.dest.read(&mut buf).await?;
			self.dest.write_all(&buf[..count]).await?;
			hasher_dest.update(&buf[..count]);
			if count != BLOCK_SIZE {
				break;
			}
		}

		if hasher_src.finalize() != hasher_dest.finalize() {
			return Err(StreamError::InvalidHash);
		}

		Ok(())
	}
}

// #[cfg(test)]
// mod tests {
// 	use tokio::fs::File;

// 	use super::*;
// 	#[tokio::test]
// 	async fn test() {
// 		stream_move_file(
// 			&mut File::open("/Users/broken/image.jpeg").await.unwrap(),
// 			&mut File::create("/Users/broken/image2.jpeg").await.unwrap(),
// 		)
// 		.await
// 		.unwrap();
// 	}
// }
