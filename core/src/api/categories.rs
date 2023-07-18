use crate::library::{get_category_count, Category};

use std::{collections::BTreeMap, str::FromStr};

use strum::VariantNames;

use super::{utils::library, Router, R};

pub(crate) fn mount() -> Router {
	R.router().procedure("list", {
		R.with2(library()).query(|(_, library), _: ()| async move {
			let mut data = BTreeMap::new();

			for category_str in Category::VARIANTS {
				let category = Category::from_str(category_str)
					.expect("it's alright this category string exists");

				data.insert(category, get_category_count(&library.db, category).await);
			}

			Ok(data)
		})
	})
}
