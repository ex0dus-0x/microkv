//! main.rs
//!
//!     Defines main application interface to the micro-kv cli.
//!     Can be used to either spin up a server instance or be used
//!     as a client that interacts with a local persistent store or
//!     one on another host and volume.

use microkv::MicroKV;

use clap::{Arg, App, SubCommand};


fn main() -> std::io::Result<()> {

    let key: &Arg = &Arg::with_name("key")
        .short("k")
        .long("key")
        .required(true)
        .takes_value(true);


    let matches = App::new("microkv")
        .version("1.0")
        .author("ex0dus <ex0dus at codemuch.tech>")

        // make program verbose
        // TODO: emit logs for auditing purposes
        .arg(Arg::with_name("debug")
             .short("d")
             .long("debug")
             .required(false)
             .help("Print out debug output")
             .takes_value(false)
        )

        // specify the name of the database to interact with
        .arg(Arg::with_name("DATABASE")
             .required(true)
             .index(1)
             .help("Name of database to interact with")
             .takes_value(false)
        )

        // interact with db without a password
        .arg(Arg::with_name("unsafe")
             .short("u")
             .long("unsafe")
             .required(false)
             .help("")
             .takes_value(false)
        )

        // `put` adds a new key and value entry.
        .subcommand(SubCommand::with_name("put")
            .about("Adds a new key and value, encrypts and adds to storage.")
            .arg(key)
            .arg(Arg::with_name("value")
                 .short("v")
                 .long("value")
                 .required(false)
                 .takes_value(true)
            )
        )

        // `get` retrieves a value by key, and decrypts it
        .subcommand(SubCommand::with_name("get")
            .about("Retrieves and decrypts value in storage by key.")
            .arg(key)
        )

        // `rm` a key-value pair by key
        .subcommand(SubCommand::with_name("rm")
            .about("Deletes a key-value pair by key")
            .arg(key)
        )
        .get_matches();

    Ok(())
}
