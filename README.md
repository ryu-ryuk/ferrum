# Ferrum 🦀

A minimal **Rust-powered backend** to detect harmful websites from a pre-defined json file.

## Lots more functionalities incoming ; )

## Current Features?

- Read & Write data from a JSON file
- Lightweight and fast
- Built with `axum` for async web handling
- Future plans: Database support, ML Integration, Authentication, and more

## Installation

Make sure you have **Rust** and **Cargo** installed:

```sh
git clone https://github.com/ryu-ryuk/ferrum.git
cd ferrum
cargo run
```

## Usage

### Send a GET request to:

```sh
curl "http://localhost:3000/checking?url=abc.in"
```
