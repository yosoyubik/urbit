#![crate_name = "rusthello"]

#[no_mangle]
pub extern fn hello_from_rust() {
    println!("Hello from Rust!");
}
