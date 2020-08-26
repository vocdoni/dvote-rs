# DVote Rust

### 0.6.0

- Adding support compressed public keys
- **Breaking**: By default `compute_public_key` now returns compressed public keys
- **Breaking**: `recover_signer` also returns compressed public keys

### 0.5.0

- Refactoring the code into separate modules

### 0.4.0

- Providing pure Rust functions (split from the FFI exports)

### 0.3.0

- Adding support for wallet management and signatures
- Rewriting functions using idiomatic Rust
