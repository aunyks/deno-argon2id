alias b := build

_default:
  @just --list --justfile {{justfile()}}

build:
  cargo build --release --target wasm32-unknown-unknown
  caber \
  ./target/wasm32-unknown-unknown/release/deno_argon2id.wasm \
  --export-mode default \
  --output-lang typescript --output-file ./argon2.wasm.ts

test: build
  cargo test
  deno test
