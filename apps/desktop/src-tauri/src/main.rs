#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
	sd_desktop_lib::run().expect("unable to run sd_desktop_lib");
}
