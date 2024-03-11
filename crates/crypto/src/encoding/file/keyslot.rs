use crate::{
	crypto::{Decryptor, Encryptor},
	rng::CryptoRng,
	types::{Aad, Algorithm, EncryptedKey, HashingAlgorithm, Key, Nonce, Salt},
	Result,
};

pub struct Keyslot {
	pub hashing_algorithm: HashingAlgorithm, // password hashing algorithm
	pub hash_salt: Salt,                     // salt to hash the password with
	pub salt: Salt,                          // the salt used for key derivation with the hash digest
	pub encrypted_key: EncryptedKey,         // encrypted
}

impl Keyslot {
	pub fn new(
		algorithm: Algorithm,
		hashing_algorithm: HashingAlgorithm,
		hash_salt: Salt,
		hashed_password: &Key,
		master_key: &Key,
		aad: Aad,
	) -> Result<Self> {
		let nonce = Nonce::generate(algorithm);
		let salt = Salt::generate();

		let encrypted_key = Encryptor::encrypt_key(
			&hashed_password.derive(salt),
			&nonce,
			algorithm,
			master_key,
			aad,
		)?;

		Ok(Self {
			hashing_algorithm,
			hash_salt,
			salt,
			encrypted_key,
		})
	}

	pub(super) fn decrypt(&self, algorithm: Algorithm, key: &Key, aad: Aad) -> Result<Key> {
		Decryptor::decrypt_key(
			&key.derive(self.salt),
			algorithm,
			&self.encrypted_key.clone(),
			aad,
		)
	}
}

impl Keyslot {
	#[must_use]
	pub fn random() -> Self {
		Self {
			hash_salt: Salt::generate(),
			hashing_algorithm: HashingAlgorithm::default(),
			encrypted_key: EncryptedKey::new(
				CryptoRng::generate_fixed(),
				Nonce::generate(Algorithm::default()),
			),
			salt: Salt::generate(),
		}
	}
}
