use std::{
	fs::{self, File},
	io::{Read, Write},
	path::PathBuf,
};

use bincode::{Decode, Encode};

use super::{keyslot::Keyslot, object::HeaderObject};
use crate::{
	encoding,
	encrypted::Encrypted,
	hashing::Hasher,
	types::{Aad, Algorithm, Key, MagicBytes, Nonce},
	Error, Protected, Result,
};

const KEYSLOT_LIMIT: usize = 2;
const OBJECT_LIMIT: usize = 2;

#[non_exhaustive]
#[derive(Copy, Clone, Encode, Decode)]
pub enum HeaderVersion {
	V1,
}

pub struct Header {
	pub version: HeaderVersion,
	pub algorithm: Algorithm,
	pub file_length: Encrypted<u64>, // encrypted true length of the file
	pub nonce: Nonce,
	pub keyslots: Vec<Keyslot>,
	pub objects: Vec<HeaderObject>,
}

impl Header {
	#[must_use]
	pub fn new(algorithm: Algorithm, file_length: Encrypted<u64>) -> Self {
		Self {
			version: HeaderVersion::V1,
			algorithm,
			file_length,
			nonce: Nonce::generate(algorithm),
			keyslots: vec![],
			objects: vec![],
		}
	}

	pub fn write_to_file<const I: usize>(
		&self,
		path: &PathBuf,
		magic_bytes: MagicBytes<I>,
	) -> Result<u64> {
		{
			let mut file = File::create_new(path)?;
			file.write_all(magic_bytes.inner().as_ref())?;
			file.flush()?;
			drop(file);

			let mut comp = cfb::create(path)?;
			comp.create_storage("/header")?;
			let mut meta = comp.create_new_stream("/header/meta")?;
			let mut keyslots = comp.create_new_stream("/header/keyslots")?;
			let mut objects = comp.create_new_stream("/header/objects")?;
			comp.create_stream("/data")?; // encrypted data

			meta.write_all(&encoding::encode(&(
				self.version,
				self.algorithm,
				self.nonce,
				self.file_length.clone(),
			))?)?;

			keyslots.write_all(&encoding::encode(&self.keyslots)?)?;
			objects.write_all(&encoding::encode(&self.objects)?)?;

			comp.flush()?;
		}

		Ok(fs::metadata(path)?.len())
	}

	pub fn from_file<const I: usize>(path: &PathBuf, magic_bytes: MagicBytes<I>) -> Result<Self> {
		let mut file = File::create_new(path)?;
		let mut mb = [0u8; I];
		file.read_exact(&mut mb)?;
		let magic_bytes_read = MagicBytes::new(mb);

		if magic_bytes != magic_bytes_read {
			return Err(Error::Validity);
		}

		todo!()
	}

	// #[must_use]
	// pub fn generate_aad(&self) -> Aad {
	// 	let mut o = [0u8; 38];
	// 	o[..2].copy_from_slice(&[0xFA, 0xDA]);
	// 	o[2..4].copy_from_slice(&self.version.as_bytes());
	// 	o[4..6].copy_from_slice(&self.algorithm.as_bytes());
	// 	o[6..38].copy_from_slice(&self.nonce.as_bytes());
	// 	Aad::Header(o)
	// }

	pub fn remove_keyslot(&mut self, index: usize) -> Result<()> {
		if index > self.keyslots.len() - 1 {
			return Err(Error::Validity);
		}

		self.keyslots.remove(index);
		Ok(())
	}

	pub fn decrypt_object(
		&self,
		name: &'static str,
		master_key: &Key,
	) -> Result<Protected<Vec<u8>>> {
		let rhs = Hasher::blake3(name.as_bytes());

		self.objects
			.iter()
			.filter_map(|o| {
				o.identifier
					.decrypt_id(master_key) // TOOD(brxken128): replace Aad::Null
					.ok()
					.and_then(|i| (i == rhs).then_some(o))
			})
			// .cloned()
			.collect::<Vec<_>>()
			.first()
			.ok_or(Error::NoObjects)?
			.decrypt(self.algorithm, Aad::Null, master_key) // TOOD(brxken128): replace Aad::Null
	}

	pub fn add_keyslot(
		&mut self,
		// hashing_algorithm: HashingAlgorithm,
		// hash_salt: Salt,
		hashed_password: &Key,
		master_key: &Key,
	) -> Result<()> {
		if self.keyslots.len() + 1 > KEYSLOT_LIMIT {
			return Err(Error::TooManyKeyslots);
		}

		self.keyslots
			.push(Keyslot::new(self.algorithm, hashed_password, master_key)?);

		Ok(())
	}

	pub fn add_object(&mut self, name: &'static str, master_key: &Key, data: &[u8]) -> Result<()> {
		if self.objects.len() + 1 > OBJECT_LIMIT {
			return Err(Error::TooManyObjects);
		}

		let rhs = Hasher::blake3(name.as_bytes());

		if self
			.objects
			.iter()
			.filter_map(|o| o.identifier.decrypt_id(master_key).ok().map(|i| i == rhs))
			.any(|x| x)
		{
			return Err(Error::TooManyObjects);
		}

		self.objects
			.push(HeaderObject::new(name, self.algorithm, master_key, data)?);
		Ok(())
	}

	pub fn decrypt_master_key(&self, keys: &[Key]) -> Result<(Key, usize)> {
		if self.keyslots.is_empty() {
			return Err(Error::NoKeyslots);
		}

		keys.iter()
			.enumerate()
			.find_map(|(i, k)| {
				self.keyslots
					.iter()
					.find_map(|z| z.decrypt(k).ok().map(|x| (x, i)))
			})
			.ok_or(Error::Decrypt)
	}

	// pub fn decrypt_master_key_with_password(
	// 	&self,
	// 	password: &Protected<Vec<u8>>,
	// ) -> Result<(Key, usize)> {
	// 	if self.keyslots.is_empty() {
	// 		return Err(Error::NoKeyslots);
	// 	}

	// 	self.keyslots
	// 		.iter()
	// 		.enumerate()
	// 		.find_map(|(i, z)| {
	// 			let k = Hasher::hash_password(
	// 				z.hashing_algorithm,
	// 				password,
	// 				z.hash_salt,
	// 				&SecretKey::Null,
	// 			)
	// 			.ok()?;
	// 			z.decrypt(&k).ok().map(|x| (x, i))
	// 		})
	// 		.ok_or(Error::Decrypt)
	// }
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;

	use crate::{
		encrypted::Encrypted,
		types::{Key, MagicBytes},
	};

	use super::Header;

	#[test]
	fn write_header() {
		let l = Encrypted::new(
			&Key::generate(),
			&128u64,
			crate::types::Algorithm::Aes256GcmSiv,
		)
		.unwrap();
		let h = Header::new(crate::types::Algorithm::Aes256GcmSiv, l);
		h.write_to_file(&PathBuf::from("test.enc"), MagicBytes::new([0u8; 6]))
			.unwrap();
	}
}
