# microkv-cli

Defines a CLI application that runs as a portable key-value store client service.

## build:

Install locally:

```
$ cargo install --path .
```

## usage

To display help options:

```
$ microkv --help
```

### local use

__microkv__ can be used to interact with a local persistent store, and works similarly to a Vault-style client.

```
$ microkv
```


### server use

The __microkv__ CLI application can also be used to run a service, exposing a port that can be interacted
with RPC calls, and committing all changes to the local persistent store on the volume it resides on.

```
$ microkv --serve 0.0.0.0:4567
```



