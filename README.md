<p align="center">
  <img src="assets/GyroJett.png" width="420">
</p>

<h1 align="center">GyroJett-OneShot2</h1>

<p align="center">
  <b>Lightweight • Secure • Privacy-focused Messenger</b>
</p>

<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-GPL--3.0-blue.svg">
  </a>
  <img src="https://img.shields.io/github/last-commit/GutGutGutGut/GyroJett-Oneshot">
  <img src="https://img.shields.io/github/stars/GutGutGutGut/GyroJett-Oneshot">
</p>

---

## About

**GyroJett-OneShot2** is an experimental, lightweight messenger written in C and designed around privacy, security and simplicity.

The project aims to keep the communication stack small, understandable and free from unnecessary services and dependencies.

No advertising.

No unnecessary telemetry.

No centralized messaging infrastructure.

Just a small, privacy-oriented messenger built from the ground up.

> **Lightweight. Secure. Private.**

## Philosophy

Modern messaging applications can become extremely complex, relying on large dependency trees, analytics, centralized infrastructure and services that users may not need.

GyroJett-OneShot2 takes a different approach.

The project is designed around:

* A small native C codebase
* Tor-native networking
* Temporary communication sessions
* Minimal persistent data
* Explicit session authentication
* End-to-end cryptographic communication
* Minimal external dependencies
* A CLI-first architecture

The command-line interface is the primary interface of the project. Other frontends may be developed in the future without replacing the underlying core.

## Architecture

The current architecture is centered around temporary Tor-based sessions.

```text
                       ┌──────────────────────────────┐
                       │      GyroJett-OneShot2       │
                       │                              │
                       │          CLI / Core          │
                       └─────────────┬────────────────┘
                                     │
                    ┌────────────────┴──────────────────┐
                    │                                   │
             ┌──────▼──────┐                     ┌──────▼──────┐
             │   Create    │                     │   Connect   │
             │   Session   │                     │   Session   │
             └──────┬──────┘                     └──────┬──────┘
                    │                                   │
                    ▼                                   ▼
             ┌──────────────┐                    ┌──────────────┐
             │    Server    │                    │    Client    │
             │              │                    │              │
             │ TCP :4242    │                    │    SOCKS5    │
             └──────┬───────┘                    └──────┬───────┘
                    │                                   │
                    └─────────────────┬─────────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │          TOR           │
                         │                        │
                         │ ControlPort :9051      │
                         │ SOCKS5 :9050           │
                         │ Onion Service          │
                         └───────────┬────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │     Session Address    │
                         │                        │
                         │        .onion          │
                         └───────────┬────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │    Authentication      │
                         │                        │
                         │    Session Secret      │
                         └───────────┬────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │    Key Establishment   │
                         │                        │
                         │   PQ / X25519 + KDF    │
                         └───────────┬────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │   Secure Messaging     │
                         │                        │
                         │     AEAD + Ratchet     │
                         └────────────────────────┘
```

The architecture is intentionally modular so that networking, session management, protocol logic and cryptographic functionality remain separated.

## Current Features

Currently implemented:

* C17 codebase
* Modular CMake project
* Ninja build support
* CLI interface
* TCP server
* TCP client
* SOCKS5 support
* Tor ControlPort integration
* Tor cookie authentication
* Dynamic Onion Service creation using `ADD_ONION`
* Ephemeral Onion Services
* 512-bit session secret generation
* Custom base-61 session secret representation
* Basic connection management
* Signal handling for `SIGPIPE`

## Planned Features

The following components are planned or under development:

* Session authentication
* Messaging protocol
* Secure handshake
* Key establishment
* End-to-end encryption
* AEAD-based message encryption
* Ratcheting protocol
* Secure file transfer
* Connection management
* Protocol validation
* Additional security hardening
* Automated testing
* Security review
* Future graphical frontend

Cryptographic primitives are intended to rely on established and audited cryptographic libraries rather than custom implementations.

## Project Status

**Early development / experimental**

GyroJett-OneShot2 is currently under active development.

The architecture is expected to evolve significantly before the first stable release.

The project should **not** currently be considered production-ready secure messaging software.

### Roadmap

* [x] Initial C project
* [x] Modular project architecture
* [x] CLI
* [x] CMake build system
* [x] Ninja build support
* [x] TCP server
* [x] TCP client
* [x] SOCKS5 support
* [x] Tor integration
* [x] Dynamic Onion Service creation
* [x] Session secret generation
* [ ] Session authentication
* [x] Messaging protocol
* [ ] Secure handshake
* [x] Key establishment
* [x] End-to-end encryption
* [ ] Ratcheting
* [ ] Secure file transfer
* [ ] Connection management
* [ ] Automated tests
* [ ] Security review
* [ ] Stable release

## Building

### Requirements

GyroJett-OneShot2 currently targets Linux.

Build dependencies:

* GCC
* GNU Binutils
* CMake >= 3.20
* Ninja
* libssl-dev
* libxeddsa-dev
* libsodium-dev
* Tor

### Clone

```bash
git clone https://github.com/GutGutGutGut/GyroJett-OneShot2.git
cd GyroJett-OneShot2
```

### Configure

```bash
cd Installer/
```

### Build

```bash
chmod +x Installer.sh
./Installer.sh
```

The resulting executable will be located at:

```text
build/GyroJett-OneShot2
```

### Run

```bash
gyrojett-oneshot2
```

## Tor Configuration

GyroJett-OneShot2 currently communicates with a local Tor instance through the Tor ControlPort and SOCKS5 interface.

The relevant Tor configuration is:

```text
ControlPort 9051
CookieAuthentication 1
```

The application uses the Tor ControlPort to dynamically create temporary Onion Services.

Static `HiddenServiceDir` configuration is not required for GyroJett-OneShot2.

The application currently uses:

```text
127.0.0.1:9051
```

for the Tor ControlPort and:

```text
127.0.0.1:9050
```

for SOCKS5 connections.

## Sessions

A GyroJett session currently consists of a temporary Onion Service and a generated session secret.

Conceptually:

```text
Session
├── Onion Service address
│
└── Session Secret
```

The Onion address identifies the network endpoint of the temporary session.

The session secret is intended to provide an additional authentication mechanism between peers.

The secret is currently generated using 512 bits of operating-system-provided randomness.

The session secret is **not currently used as a message-encryption key**.

Authentication and cryptographic key establishment are separate protocol stages and are still under development.

## Security

Security is one of the primary goals of GyroJett-OneShot2.

The project aims to minimize:

* Metadata exposure
* Persistent message storage
* Unnecessary network communication
* Dependency complexity
* User tracking
* Centralized infrastructure

Tor provides the network transport layer, while application-level cryptography is intended to provide protection for the actual communication protocol.

### Important

**GyroJett-OneShot2 has not undergone a professional security audit.**

Do not assume that the application is secure simply because it uses Tor or cryptography.

Security-sensitive software requires extensive testing, protocol analysis, code review and independent auditing.

The current software should be considered experimental.

## Privacy

GyroJett-OneShot2 is designed around the principle of minimizing unnecessary data collection.

Privacy goals include:

* No advertising
* No behavioral tracking
* Minimal logging
* Minimal persistent messaging data
* Tor-based networking
* Temporary communication sessions
* Minimal external dependencies

Privacy guarantees depend on the final implementation and protocol design and should not be considered complete at the current development stage.

## Project Structure

```text
GyroJett-OneShot/
├── CMakeLists.txt          # Main CMake build script
├── README.md               # Project documentation and roadmap
├── LICENSE                 # GNU General Public License v3.0
├── cross_platform.h        # Platform abstraction layer definitions
├── Installer/
│   └── Installer.sh        # Automated build and deployment script for Debian
└── src/
    ├── main.c              # Application entry point and module initialization
    ├── chat/
    │   ├── chat.h          # Chat loop definitions and buffer boundaries
    │   └── chat.c          # Terminal and network I/O multiplexing (select)
    ├── cli/
    │   ├── cli.h           # Command-line interface function prototypes
    │   └── cli.c           # CLI parsing, user menus, and terminal interaction
    ├── client/
    │   ├── client.h        # SOCKS5 outbound client initialization
    │   └── client.c        # Outbound TCP connections routed through the Tor network
    ├── core/
    │   ├── core.h          # Global lifecycle definitions and structures
    │   └── core.c          # Central orchestrator connecting networking and crypto
    ├── crypto/
    │   ├── aead.h / aead.c             # Authenticated Encryption with Associated Data (AEAD)
    │   ├── crypto.h / crypto.c         # Entropy pooling and anti-forensic secure memory zeroing
    │   ├── mlkem.h / mlkem.c           # Module-Lattice-Based Key Encapsulation Mechanism (Post-Quantum KEM)
    │   ├── x25519.h / x25519.c         # Traditional Curve25519 Elliptic Curve Cryptography
    │   ├── xeddsa.h / xeddsa.c         # Ed25519/Curve25519 cryptographic signatures
    │   └── xeddsa_platform.h           # Architecture-specific macros for XEDDSA performance
    ├── handshake/
    │   ├── pqxdh.h         # Post-Quantum Extended Diffie-Hellman (Híbrid) protocol definitions
    │   └── pqxdh.c         # Modular cryptographic handshake and initial key exchange
    ├── identity/
    │   ├── identity.h      # User identity key structures and cryptographic profiles
    │   └── identity.c      # Long-term cryptographic identity generation and persistence
    ├── network/
    │   ├── connection.h / connection.c # Low-level TCP socket wrappers and stream buffering
    │   └── socks5.h / socks5.c         # Native SOCKS5 protocol handshake and state machine
    ├── protocol/           # Package serialization, framing, and data encapsulation
    ├── ratchet/            # Double Ratchet algorithm implementation for session forward secrecy
    ├── server/
    │   ├── server.h        # Inbound TCP server initialization
    │   └── server.c        # Inbound connection management from ephemeral Onion Services
    ├── session/
    │   ├── secret.h        # Ephemeral session key entropy definitions
    │   └── session.c       # Secure generation of volatile session secrets in base-61
    └── tor/
        ├── tor.h           # Tor daemon management and control primitives
        └── tor.c           # Tor ControlPort 9051 interaction and dynamic Onion Services (ADD_ONION)

```

The architecture is intentionally modular so that new protocol, cryptographic and identity components can be added without turning the application into a monolithic codebase.

## Contributing

Contributions, ideas, bug reports and security reviews are welcome.

To contribute:

```bash
git clone https://github.com/GutGutGutGut/GyroJett-OneShot.git
cd GyroJett-OneShot2
```

Create a branch:

```bash
git checkout -b feature/my-feature
```

Build and test your changes before submitting a pull request.

Please keep the project:

* Lightweight
* Modular
* Understandable
* Security-conscious
* Free from unnecessary dependencies

## License

GyroJett-OneShot2 is free and open-source software.

Licensed under the **GNU General Public License v3.0**.

See [`LICENSE`](LICENSE) for the complete license.

## Disclaimer

GyroJett-OneShot2 is experimental software.

It is provided **"as is"**, without warranty of any kind.

The project has not been professionally audited and should not be relied upon for highly sensitive or safety-critical communications.

---

<p align="center">
  <b>GyroJett-OneShot2</b>
  <br>
  <sub>Lightweight. Secure. Privacy-focused.</sub>
</p>

