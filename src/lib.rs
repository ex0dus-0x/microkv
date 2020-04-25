//! lib.rs
//!
//!     Defines modules within library crates
//!     that can be exported for interfacing.

extern crate bincode;
extern crate serde;
extern crate secrets;

pub mod kv;
pub mod errors;

use crate::kv::MicroKV;

/*
/// `Mode` defines the state that the `App` should run as.
/// TODO
enum Mode {
    Client,
    Server
}


/// `App` defines an interactable object for client implementations that
/// wish to interface with a micro-kv store instance. While this will be primarily
/// used by the PoC cli app, this should be extensible for any small deployable
/// microservices that use to harness micro-kv.
pub struct App {
    datastore: MicroKV,
    mode: Mode,
    host: String,
    port: u32,
}

impl Default for App {
    fn default() -> App {
        unimplemented!();
    }
}


impl App {

    fn init(address: Option<String>) -> App {
        unimplemented!();
    }

    fn serve(&self) -> () {
        unimplemented!();
    }
}
*/
