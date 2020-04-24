//! lib.rs
//!
//!     Defines modules within library crates
//!     that can be exported for interfacing.

pub mod kv;
pub mod errors;

use crate::kv::MicroKV;


/// `App` defines an interactable object for client implementations that
/// wish to interface with a micro-kv store instance. While this will be primarily
/// used by the PoC cli app, this should be extensible for any small deployable
/// microservices that use to harness micro-kv.
pub struct App {
    datastore: MicroKV,
    host: String,
    port: u32,
}


impl App {

    fn init(address: Option<String>) -> App {
        unimplemented!();
    }

    fn serve(&self) -> () {
        unimplemented!();
    }
}
