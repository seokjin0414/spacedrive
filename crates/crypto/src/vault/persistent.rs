#![allow(dead_code)]

use std::path::PathBuf;

use redb::{Database, ReadableTable, TableDefinition};

use crate::{
	encoding,
	encrypted::Encrypted,
	types::{Algorithm, Key, Salt},
	Error, Result,
};

const SECRET_KEY_TABLE: TableDefinition<'_, &'_ [u8; 32], Vec<u8>> =
	TableDefinition::new("secret_keys");
const META_TABLE: TableDefinition<'_, &'_ str, Vec<u8>> = TableDefinition::new("meta");
const KEY_MANAGER_TABLE: TableDefinition<'_, &'_ str, Vec<u8>> =
	TableDefinition::new("key_manager");

const ROOT_KEY_ID: &str = "root_key";
const ROOT_SALT_ID: &str = "root_salt";

pub struct Vault {
	db: Database,
	key: Option<Key>,
}

impl Vault {
	pub fn open(path: PathBuf, key: Option<Key>) -> Result<Self> {
		let db = Database::create(path)?;

		let txn = db.begin_write()?;
		{
			txn.open_table(SECRET_KEY_TABLE)?;
			txn.open_table(META_TABLE)?;
		}
		txn.commit()?;

		Ok(Self { db, key })
	}

	pub fn setup(&self, key: &Key, algorithm: Option<Algorithm>) -> Result<()> {
		// provided key should be master password, (generated) salt (store that in here, like have a `retrieve decrypt info`),
		// and the vault key from the OS keyring. the vault key/pepper will have to be provided manually if OS keyrings/the key isn't available.
		// can use a QR code, or copy/paste/type (last resort) the 16-byte (hex encoded) key

		let algorithm = algorithm.unwrap_or_default();

		let root_key = Key::generate();
		let salt = Salt::generate();

		let encrypted_key = Encrypted::new(key, &root_key, algorithm)?;

		let txn = self.db.begin_write()?;

		{
			let mut table = txn.open_table(META_TABLE)?;
			if table.get(ROOT_KEY_ID).is_ok() || table.get(ROOT_SALT_ID).is_ok() {
				return Err(Error::RootKeyAlreadyExists);
			}

			table.insert(ROOT_KEY_ID, encrypted_key.as_bytes()?)?;
			table.insert(ROOT_SALT_ID, encoding::encode(&salt)?)?;
		}

		txn.commit()?;

		Ok(())
	}

	pub fn unlock(&mut self, key: &Key) -> Result<()> {
		let txn = self.db.begin_read()?;

		let table = txn.open_table(META_TABLE)?;

		let rk = table
			.get(ROOT_KEY_ID)?
			.ok_or(Error::RootKeyDoesntExist)?
			.value();

		let root_key = Encrypted::<Key>::from_bytes(&rk)?.decrypt(key)?;

		self.key = Some(root_key);

		Ok(())
	}

	/// Use the salt returned from here with the master password and
	/// the pepper ("vault key") can be retrieved from the OS keyring. This will get you the key for the vault.
	/// From there you can retrieve the secret key, and hash that with the master password in order to unlock the key manager
	pub fn get_salt(&self) -> Result<Salt> {
		let txn = self.db.begin_read()?;

		let table = txn.open_table(META_TABLE)?;

		let rs = table
			.get(ROOT_SALT_ID)?
			.ok_or(Error::RootKeyDoesntExist)?
			.value();

		encoding::decode(&rs)
	}

	pub fn wipe(self) -> Result<()> {
		todo!()
	}

	#[inline]
	pub const fn is_unlocked(&self) -> bool {
		self.key.is_some()
	}

	#[inline]
	pub fn is_setup(&self) -> Result<bool> {
		let txn = self.db.begin_read()?;
		let table = txn.open_table(META_TABLE)?;
		Ok(table.get(ROOT_KEY_ID).is_ok() && table.get(ROOT_SALT_ID).is_ok())
	}
}
