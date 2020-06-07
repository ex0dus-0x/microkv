//! Defines main application interface to the micro-kv cli. Can be used to either spin up a
//! server instance or be used as a client that interacts with a local persistent store or
//! one on another host and volume.

use std::path::PathBuf;

use microkv::errors::Result;
use microkv::MicroKV;

use clap::{App, Arg, ArgMatches, SubCommand};

fn parse_args<'a>() -> ArgMatches<'a> {
    // define key arg to avoid repetition
    let key: &Arg = &Arg::with_name("key")
        .short("k")
        .long("key")
        .required(true)
        .takes_value(true);

    App::new("microkv-cli")
        .version("0.2.3")
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
             .help("Name of database to interact with. Will be created if doesn't exist.")
             .takes_value(false)
        )

        // interact with db without a password
        .arg(Arg::with_name("unsafe")
             .short("u")
             .long("unsafe")
             .required(false)
             .help("Interact with the database without encryption.")
             .takes_value(false)
        )

        // instantiate a server based off of the current KV in context
        .arg(Arg::with_name("server")
             .short("s")
             .long("server")
             .required(false)
             .help("If specified, will initialize a HTTP service for interacting with KV. (if no address, default is 0.0.0.0:8080).")
             .takes_value(true)
        )

        // `put` adds a new key and value entry.
        .subcommand(SubCommand::with_name("put")
            .about("Adds a new key and value, encrypts and adds to storage.")
            .arg(key)
            .arg(Arg::with_name("value")
                 .short("v")
                 .long("value")
                 .required(true)
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

        // `list` prints out all keys within the database
        .subcommand(SubCommand::with_name("list")
            .about("List out keys existing in the database")
            .arg(Arg::with_name("sorted")
                 .short("s")
                 .long("sorted")
                 .required(false)
                 .takes_value(false)
                 .help("Print out keys in sorted order")
            )
            .arg(Arg::with_name("values")
                .short("v")
                .long("values")
                .required(false)
                .takes_value(false)
                .help("Include values when printing")
            )
        )
        .get_matches()
}

#[tokio::main]
async fn run_server(addr: Vec<u8>, port: u64, kv: MicroKV, debug: bool) -> Result<'static, ()> {
    todo!();
}

fn run() -> Result<'static, ()> {
    let args: ArgMatches = parse_args();

    // check if debug is set
    let debug: bool = args.is_present("debug");

    // check if database file exists
    let database: &str = args.value_of("DATABASE").unwrap();
    let dbpath: PathBuf = MicroKV::get_db_path(database);

    // initialize key-value object through database name
    let mut kv: MicroKV = match dbpath.as_path().exists() {
        true => MicroKV::open(database)?,
        false => MicroKV::new(database),
    };

    // TODO: consume structured inputs either as string format or file

    // safely parse password unless --unsafe set
    if !args.is_present("unsafe") {
        let pass = rpassword::read_password_from_tty(Some("Password: ")).unwrap();
        kv = kv.with_pwd_clear(pass);
    }

    // spin up a HTTP server if set, ignoring all other arguments. If not set,
    // initialize as 0.0.0.0:8080
    if args.is_present("server") {
        // get server address
        let (server_addr, port): (Vec<u8>, u64) = match args.value_of("server") {
            Some(server) => {
                // split into address and port
                let split: Vec<&str> = server.split(":").collect::<Vec<&str>>();

                // turn address string into Vec<u8>
                let addr: Vec<u8> = split[0]
                    .split(".")
                    .map(|x| x.parse::<u8>().unwrap())
                    .collect::<Vec<u8>>();

                (addr, split[1].parse::<u64>().unwrap())
            }
            None => (vec![0u8; 4], 8080),
        };

        // initialize server with error-handling
        run_server(server_addr, port, kv, debug)?;
        return Ok(());
    }

    // otherwise, interact with local db normally
    match args.subcommand() {
        ("put", Some(subargs)) => {
            let key: &str = subargs.value_of("key").unwrap();
            let value: &str = subargs.value_of("value").unwrap();

            kv.put(key, value)?;
            println!("Inserting key-value entry into database `{}`", database);
            kv.commit()?;
        }
        ("get", Some(subargs)) => {
            let key: &str = subargs.value_of("key").unwrap();

            let value: String = kv.get::<String>(key)?;
            println!("{}", value);
        }
        ("rm", Some(subargs)) => {
            let key: &str = subargs.value_of("key").unwrap();

            kv.delete(key)?;
            println!("Removed entry by key `{}`", key);
            kv.commit()?;
        }
        ("list", Some(subargs)) => {
            let keys: Vec<String> = match subargs.is_present("sorted") {
                true => kv.sorted_keys()?,
                false => kv.keys()?,
            };
            println!("Keys Present in Database:");
            for key in keys {
                println!("{}", key);
            }
        }
        _ => {}
    }

    Ok(())
}

fn main() {
    match run() {
        Err(e) => eprintln!("{}", e),
        _ => {}
    }
}
