use bincode::{Decode, Encode};

use crate::{
	crypto::{Decryptor, Encryptor},
	encrypted::Encrypted,
	hashing::Hasher,
	types::{Aad, Algorithm, Key, Nonce},
	Protected, Result,
};

#[derive(Clone, Encode, Decode)]
pub struct HeaderObjectIdentifier(pub(super) Encrypted<Key>);

#[derive(Encode, Decode)]
pub struct HeaderObject {
	pub identifier: HeaderObjectIdentifier,
	pub nonce: Nonce,
	pub data: Vec<u8>,
}

impl HeaderObject {
	pub fn new(
		name: &'static str,
		algorithm: Algorithm,
		master_key: &Key,
		data: &[u8],
	) -> Result<Self> {
		let identifier = HeaderObjectIdentifier::new(name, master_key, algorithm)?;

		let nonce = Nonce::generate(algorithm);
		let encrypted_data =
			Encryptor::encrypt_bytes(master_key, &nonce, algorithm, data, Aad::Null)?;

		let object = Self {
			identifier,
			nonce,
			data: encrypted_data,
		};

		Ok(object)
	}

	pub(super) fn decrypt(
		&self,
		algorithm: Algorithm,
		aad: Aad,
		master_key: &Key,
	) -> Result<Protected<Vec<u8>>> {
		Decryptor::decrypt_bytes(master_key, &self.nonce, algorithm, &self.data, aad)
	}
}

impl HeaderObjectIdentifier {
	pub fn new(name: &'static str, master_key: &Key, algorithm: Algorithm) -> Result<Self> {
		Ok(Self(
			Hasher::blake3(name.as_bytes()).encrypt(master_key, algorithm)?,
		))
	}

	pub(super) fn decrypt_id(&self, master_key: &Key) -> Result<Key> {
		self.0.clone().decrypt(master_key)
	}
}
