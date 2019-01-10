#![crate_name = "rusthello"]

extern crate regex;

use regex::Regex;

// #[no_mangle]
// pub extern fn hello_from_rust() {
pub fn main() {
    let re = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
    println!("Hello from Rust!");
    println!("Did our date match our regex? {}", re.is_match("2014-01-01"));
}
