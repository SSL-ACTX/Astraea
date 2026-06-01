# Astraea

**Security Middleware for Node.js**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Zig](https://img.shields.io/badge/Zig-0.17.0-blue.svg)](https://ziglang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-Supported-green.svg)](https://nodejs.org/)

> [!IMPORTANT]
> Astraea is currently in active development and intended for security research and development environments.

---

Astraea is a high-performance security middleware for Node.js. It implements an Object-Capability (O-Cap) enforcement layer at the native C-ABI boundary, protecting applications from supply-chain attacks, Remote Code Execution (RCE) exploits, and unauthorized data access.

## Table of Contents
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Performance](#performance)
- [Security Disclaimer](#security-disclaimer)

---

## Key Features

*   **Native Interception:** Hooks `libuv` and `libc` system calls (`open`, `connect`, `dlopen`, `execve`, etc.) using dynamic linker hijacking.
*   **Context-Aware Attribution:** Automatically correlates native I/O and network requests back to the specific JavaScript module or package via V8 stack introspection.
*   **Modular Security Mesh:** Separate managers for Filesystem, Networking, Process/Environment, Attribution, and Kernel-level Hardening.
*   **Path Matching:** High-performance, Regex-backed path matching via the `globset` crate, ensuring absolute path canonicalization.
*   **Network Enforcement:** Hybrid domain and CIDR-based filtering with granular protocol and port range rules.
*   **Seccomp-BPF Protection:** Kernel-level sandbox enforcing a strict syscall whitelist to prevent native bypasses, direct kernel escapes, and unhandled behaviors.
*   **Process & Environment Control:** Restricts unauthorized processes from executing subprocesses or altering the environment.
*   **Observability:** Built-in asynchronous audit logging and telemetry streaming via `astraea-daemon`.
*   **Capability Spoofing:** Redirection of unauthorized access to synthetic mock data instead of failing.

---

## Architecture

Astraea utilizes a modular design:

1.  **Interceptor (Zig):** A lightweight C-ABI wrapper that hijacks system calls and forwards context to the engine.
2.  **Engine (Rust):** The core orchestrator, featuring:
    *   **FsManager:** Manages robust glob-based filesystem capabilities.
    *   **NetManager:** Handles networking rules and socket bounds.
    *   **ProcEnvManager:** Controls child processes and environment variables.
    *   **Attribution Engine:** Performs deep V8 stack introspection.
    *   **Guardian:** Generates and applies Seccomp-BPF filters.
    *   **Audit/Telemetry:** Streams real-time enforcement logs.

---

## Documentation

Technical specifications and research documentation can be found in the `docs/` directory:

- [**Architectural Specification & Roadmap**](docs/plans/astraea_architecture_specification.md): Detailed overview of the O-Cap model, technical stack, and implementation phases.
- [**Performance Analysis**](docs/benchmarks/astraea_performance.md): Formal benchmarking results and overhead breakdown for native interception and policy evaluation.

---

## Getting Started

### Prerequisites

*   **Zig:** Version 0.17.0 (strictly required)
*   **Rust:** Version 1.75.0 or later
*   **Node.js**
*   **Clang** (for final linking)

### Building

To build the project in optimized release mode:

```bash
zig build -Doptimize=ReleaseFast
```

The resulting library will be located at `zig-out/lib/libastraea.so`.

### Usage

Inject Astraea into any Node.js process using `LD_PRELOAD`:

```bash
RUST_LOG=astraea=info LD_PRELOAD=./zig-out/lib/libastraea.so node your-app.js
```

---

## Configuration (`astraea.toml`)

Policies are defined in a TOML manifest, allowing restriction by package name or the `root` application package.

```toml
[packages.root]
fs = ["read:package.json", "read:src/**"]
native_addons = ["*.node"]
network = ["allow:api.github.com:443", "allow:127.0.0.1:53"]

[packages.axios]
network = ["allow:*.github.com:*"]

[seccomp]
allowed_syscalls = ["ptrace"]

[spoofs]
"config/secrets.json" = "{\"key\": \"mocked_value\"}"
```

---

## Performance

Astraea is designed for high-throughput environments. Current benchmarks indicate an average overhead of ~0.03ms per intercepted call, fitting within high-performance Node.js requirements.

---

## Security Disclaimer

Astraea is a security research project. It provides robust protection at the `libuv` layer and enforces a Linux `seccomp-bpf` filter to block unauthorized direct syscalls at the kernel level, mitigating bypasses via custom native addons. It should be evaluated in staging environments prior to any production deployment.

---

<div align="center">

Built with 🦀 & ⚡ by [Seuriin](https://github.com/SSL-ACTX)

</div>
