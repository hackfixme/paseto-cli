# paseto-cli

This is a command-line tool for working with [Platform-Agnostic Security Tokens](https://paseto.io/). It is a lightweight wrapper around the [go-paseto library](https://github.com/aidantwoods/go-paseto).


## Features

- Create local and public PASETO v2, v3, and v4 keys in hex and PEM encodings.
- Create signed and encrypted tokens with custom claims.
- Parse and validate tokens, with optional time skew tolerance.
- User-friendly command-line interface.
- Cross-platform: runs on Linux, macOS and Windows.


## Installation

You can install it in one of two ways:

- Download a pre-built package for your system from the latest release on the [releases page](https://github.com/hackfixme/paseto-cli/releases), and extract the `paseto` binary to a directory on your `$PATH`.

- Build a binary for your system yourself.

  First, ensure you have [Git](https://github.com/git-guides/install-git) and [Go](https://golang.org/doc/install) installed. Go must be version 1.24 or later.

  Then in a terminal run:

  ```sh
  go install go.hackfix.me/paseto-cli/cmd/paseto@latest
  ```


## Usage

### Key generation

The `genkey` command creates new keys.

Arguments:
-  `<protocol-purpose>`: PASETO protocol purpose; "local" for shared-key (symmetric) encryption or "public" for public-key (asymmetric) signing.

Flags:
- `-v`, `--protocol-version="4"`: Version of the PASETO protocol. Valid values: 2,3,4
- `-o`, `--out-file=STRING`: Base file path to write the key(s) to; stdout will be used if not specified.
- `-e`, `--encoding="hex"`: Encoding type. Valid values: hex,pem


Examples:
- Create a v4 public key pair and output them to stdout in hexadecimal format:
  ```sh
  $ paseto genkey public
  Private key: c771ec8b6edd17878e7e9c5bdc5c482f0710400b3b5de44051a41c8b72ceba059c2efd9df74f3d48e0814d102726b042923280a73b6272d6bae7ed9f694ec332
  Public key: 9c2efd9df74f3d48e0814d102726b042923280a73b6272d6bae7ed9f694ec332
  ```

- Create a v4 public key pair and save them to `v4-priv.key` and `v4-pub.key` files in hexadecimal encoding:
  ```sh
  $ paseto genkey public --out-file v4
  ```

- Create a v3 symmetric key and save it to a `v3-sym.key` file in PEM format:
  ```sh
  $ paseto genkey local --protocol-version 3 --out-file v3 --encoding pem
  ```


### Creating signed tokens

The `sign` command creates signed tokens using a private key file created by the `genkey public` command.

Flags:
- `-v`, `--protocol-version="4"`: Version of the PASETO protocol. Valid values: 2,3,4
- `-k`, `--key-file=STRING`: Path to a private key file to sign the token.
- `-e`, `--expiration=1h`: Token expiration as a duration from now (e.g. 5m, 1h, 3d, 1M3d, 1Y) or a future timestamp in RFC 3339 format (e.g. 2025-06-18T00:00:00Z).
- `-c`, `--claim=CLAIM`: key=value pair to add to the token (e.g. role=admin), or '-' to read claims as JSON from stdin. Can be specified multiple times.

Examples:
- Create a signed v4 token which expires one hour from now:
  ```sh
  $ paseto sign --key-file v4-priv.key \
      v4.public.eyJleHAiOiIyMDI1LTA2LTE3VDEzOjAwOjAwWiIsImlhdCI6IjIwMjUtMDYtMTdUMTI6MDA6MDBaIiwibmJmIjoiMjAyNS0wNi0xN1QxMjowMDowMFoifXMMUWTRJKhb0l5upxXaGVS0ZjZEVfgjO22K74N89MuOrWzTAsHvOSXVBXbV7_7kp0KwBIrhCrBZYwVu5iSaQAc
  ```

- Create a signed v4 token with custom claims which expires one week from now:
  ```sh
  $ paseto sign --key-file v4-priv.key --claim role=admin --expiration=1w \
      v4.public.eyJleHAiOiIyMDI1LTA2LTI0VDEyOjAwOjAwWiIsImlhdCI6IjIwMjUtMDYtMTdUMTI6MDA6MDBaIiwibmJmIjoiMjAyNS0wNi0xN1QxMjowMDowMFoiLCJyb2xlIjoiYWRtaW4ifQgLXjFzQ-Plrr7DDgOCuuZNxur7KSkaiYCYhoEn-4uY1pc3qIqwKq1CF4CBwqHmplNuzP9RZvZR-n9sZmzGOQM
  ```

- Create a signed v3 token with custom claims from JSON which expires in October 2025:
  ```sh
  $ echo '{"exp":"2025-10-01T10:00:00Z","iat":"2025-06-17T12:00:00Z","nbf":"2025-06-17T12:00:00Z","role":"admin","priority":1}' \
    | paseto sign --protocol-version 3 --key-file v3-priv.key --claim - --claim sub=Bob
  v3.public.eyJleHAiOiIyMDI1LTEwLTAxVDEwOjAwOjAwWiIsImlhdCI6IjIwMjUtMDYtMTdUMTI6MDA6MDBaIiwibmJmIjoiMjAyNS0wNi0xN1QxMjowMDowMFoiLCJwcmlvcml0eSI6MSwicm9sZSI6ImFkbWluIiwic3ViIjoiQm9iIn2q6KeNntB3mMmHqUnlpXmuPgcK_nQ4owJ7m4AC7q3HAwcMIdY0myT4HpTyDQusGxHJGwYaZEVhXeJ857tw2cDz8Y2kDqMjd4VDyPGvEMU8XCtk2CW2VBySnZ2CzNVWVSk
  ```


### Creating encrypted tokens

The `encrypt` command creates encrypted tokens using a symmetric key file created by the `genkey local` command. The usage is the same as the `sign` command.

Flags:
- `-v`, `--protocol-version="4"`: Version of the PASETO protocol. Valid values: 2,3,4
- `-k`, `--key-file=STRING`: Path to a symmetric key file to encrypt the token.
- `-e`, `--expiration=1h`: Token expiration as a duration from now (e.g. 5m, 1h, 3d, 1M3d, 1Y) or a future timestamp in RFC 3339 format (e.g. 2025-06-18T00:00:00Z).
- `-c`, `--claim=CLAIM`: key=value pair to add to the token (e.g. role=admin), or '-' to read claims as JSON from stdin. Can be specified multiple times.

Examples:
- Create an encrypted v3 token which expires three days from now:
  ```sh
  $ paseto encrypt --protocol-version 3 --key-file v3-sym.key --expiration 3d \
      v3.local.DJnSz6coQrj4eNIS0JyUju-Txmz5s96RysB72gW8GDCudMWerQq5yzkg5g0bi081VwpE6_5CkNNruY_276kh-kA79yqpvnjyQ8ZAZw_sfcD7y8rVJFdFAa1KWF5kEiJcq6B45ZPYzPIHrg7FF_xALgeWI_IMPetgJQj7Pzy_1lnT1Ipr5C1D-BFk6M4uov9pTeX_B3GgdzJGZfFV1mxOSc8FPlKvuqnP
  ```


### Parsing tokens

The `parse` command parses, verifies or decrypts tokens, optionally validates them, and writes their claim data to stdout. Validation is enabled by default, but it can be disabled by passing `--no-validate`.

Flags:
- `-k`, `--key-file=STRING`: Path to a key file to verify or decrypt the token (public key for signed tokens, shared key for encrypted tokens).
- `-o`, `--output-format="text"`: Token output format. Valid values: text,json
- `--[no-]validate`: Whether to validate the token.
- `-t`, `--time-skew-tolerance=30s`: Amount of time to allow token claim times (iat, nbf, exp) to be from the current system time to account for clock skew between systems.

Examples:
- Parse, verify, and validate a signed v4 token:
  ```sh
  $ paseto parse --key-file v4-pub.key \
      v4.public.eyJleHAiOiIyMDI1LTA2LTI0VDEyOjAwOjAwWiIsImlhdCI6IjIwMjUtMDYtMTdUMTI6MDA6MDBaIiwibmJmIjoiMjAyNS0wNi0xN1QxMjowMDowMFoiLCJyb2xlIjoiYWRtaW4ifQgLXjFzQ-Plrr7DDgOCuuZNxur7KSkaiYCYhoEn-4uY1pc3qIqwKq1CF4CBwqHmplNuzP9RZvZR-n9sZmzGOQM
  Issued At:   2025-06-17 12:00:00 +0000 UTC
  Not Before:  2025-06-17 12:00:00 +0000 UTC
  Expiration:  2025-06-24 12:00:00 +0000 UTC
  
  Custom Claims
  -------------
  role:  admin
  ```

- Parse, decrypt, and validate an encrypted v3 token, and output its claim data in JSON format:
  ```sh
  $ paseto parse --key-file v3-sym.key --output-format json \
      v3.local.DJnSz6coQrj4eNIS0JyUju-Txmz5s96RysB72gW8GDCudMWerQq5yzkg5g0bi081VwpE6_5CkNNruY_276kh-kA79yqpvnjyQ8ZAZw_sfcD7y8rVJFdFAa1KWF5kEiJcq6B45ZPYzPIHrg7FF_xALgeWI_IMPetgJQj7Pzy_1lnT1Ipr5C1D-BFk6M4uov9pTeX_B3GgdzJGZfFV1mxOSc8FPlKvuqnP
  {
    "exp": "2025-06-20T12:00:00Z",
    "iat": "2025-06-17T12:00:00Z",
    "nbf": "2025-06-17T12:00:00Z"
  }
  ```


## License

[MIT](/LICENSE)
