alias b := build
default:
  just --list

build:
  cargo build --release --target wasm32-unknown-unknown
  caber \
  ./target/wasm32-unknown-unknown/release/cryptosaurus.wasm \
  --export-mode default \
  --output-lang typescript --output-file ./argon2.wasm.ts

test: build
  cargo test
  deno test
