#!/bin/sh

# Install the Rust nightly toolchain with minimal profile (for advanced features)
rustup toolchain install nightly --profile=minimal

# Add the Rust formatter (rustfmt) for the nightly toolchain
rustup component add --toolchain nightly rustfmt 
