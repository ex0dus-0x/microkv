//! main.rs
//!
//!     Defines main application interface to the micro-kv cli.
//!     Can be used to either spin up a server instance or be used
//!     as a client that interacts with a local persistent store or
//!     one on another host and volume.

extern crate microkv;

use microkv::MicroKV;

fn main() -> std::io::Result<()> {

    let unsafe_pwd: String = String::from("password123");

    let db = MicroKV::new("default")
        .with_pwd_clear(unsafe_pwd);

    db.put("test", 1).unwrap();
    db.put("test", 1).unwrap();
    println!("{}", db.get::<i32>("test").unwrap());
    db.commit()?;
    Ok(())
}
