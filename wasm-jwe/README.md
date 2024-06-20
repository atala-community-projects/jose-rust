# JWE Rust

## Under the hood

This package is written in Rust using [didcomm](<(https://img.shields.io/crates/v/didcomm)>) crate. It compiles
to `wasm32` and exposes Javascript/Typescript API with [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen) help.
Also [wasmp-pack](https://github.com/rustwasm/wasm-pack) helps in packaging and publishing.

## Building from source

For browser
``` 
wasm-pack build --target=web
```

For node
``` 
wasm-pack build --target=nodejs
```