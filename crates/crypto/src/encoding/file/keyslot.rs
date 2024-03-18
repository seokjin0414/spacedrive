use bincode::{Decode, Encode};

use crate::{
	encrypted::Encrypted,
	types::{Algorithm, Key},
	Result,
};

#[derive(Encode, Decode)]
pub struct Keyslot(Encrypted<Key>);

impl Keyslot {
	pub fn new(algorithm: Algorithm, hashed_password: &Key, master_key: &Key) -> Result<Self> {
		let encrypted_key = master_key.clone().encrypt(&hashed_password, algorithm)?;

		Ok(Self(encrypted_key))
	}

	pub(super) fn decrypt(&self, key: &Key) -> Result<Key> {
		self.0.clone().decrypt(key)
	}
}
