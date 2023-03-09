# phishing-bait
A program to help speed up the process of reporting phishing domains.

## Installation
Make sure you have `cargo` installed with a recent version of Rust, and run:
```sh
$ cargo install --git https://github.com/booleancoercion/phishing-bait --tag v0.1
```

## Usage
Simply run `phishing-bait` in your favorite terminal after installation, and provide the malicious URLs as arguments.

`phishing-bait` will retrieve the relevant information for each URL on its own (notably the registrar's abuse contact email),
and automatically output a list of email bodies that you can send as-is to the relevant addresses. Note that `phishing-bait` reports nothing
on its own - you must manually contact and report each domain. This tool merely exists to ease that process.

## License

Licensed under either of:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
