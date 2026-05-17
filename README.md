# Astraea (Experimental)

**Astraea** is a high-performance, zero-trust security middleware for Node.js. It implements an **Object-Capability (O-Cap)** enforcement layer at the native C-ABI boundary, protecting applications from supply-chain attacks, RCE exploits, and unauthorized data access.

> [!IMPORTANT] 
> Astraea is currently in active development. While functional, it is intended for security research and development environments.

---

## Key Features

*   **Native Interception:** Hooks `libuv` and `libc` system calls (`open`, `connect`, `dlopen`, etc.) using dynamic linker hijacking.
*   **Context-Aware Attribution:** Automatically correlates native I/O and network requests back to the specific JavaScript module/package via V8 stack introspection.
*   **Modular Security Mesh:** Cleanly separated architecture with dedicated managers for Filesystem, Networking, Attribution, and Kernel-level Hardening.
*   **Robust Globset Matching:** High-performance, Regex-backed path matching via the `globset` crate, ensuring absolute path canonicalization.
*   **Smart Network Enforcement:** Hybrid domain and CIDR-based filtering with a "Smart DNS Verifier" to solve the blind-IP problem on Android.
*   **Seccomp-BPF Protection:** Kernel-level sandbox enforcing a strict syscall whitelist to prevent native bypasses and direct kernel escapes.
*   **Capability Spoofing:** Seamlessly redirects unauthorized access to synthetic mock data instead of failing.

---

## Architecture

Astraea leverages a modular architecture:

1.  **The Interceptor (Zig):** A lightweight C-ABI wrapper that hijacks system calls and forwards context to the engine.
2.  **The Engine (Rust):** The core orchestrator, featuring:
    *   **FsManager:** Manages robust glob-based filesystem capabilities.
    *   **NetManager:** Handles CIDR-based networking and DNS-to-IP verification.
    *   **Attribution Engine:** Performs deep V8 stack introspection.
    *   **Guardian:** Generates and applies Seccomp-BPF filters.

---

## Getting Started


Explore the technical specifications and research in the [`docs/`](docs/) directory:

- [**Architectural Specification & Roadmap**](docs/plans/plan.md): Detailed overview of the O-Cap model, technical stack, and implementation phases.
- [**Performance Analysis**](docs/benchmarks/PERFORMANCE.md): Formal benchmarking results and overhead breakdown for native interception and policy evaluation.

---

## Getting Started

### Prerequisites

*   **Zig** (0.13.0 or later)
*   **Rust** (1.75.0 or later)
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

Policies are defined in a simple TOML manifest. You can restrict access by package name or use the `root` package for the main application.

```toml
[packages.root]
fs = ["read:package.json", "read:src/**"]
native_addons = ["*.node"]
network = ["allow:api.github.com:443", "allow:127.0.0.1:53"]

[packages.axios]
network = ["allow:*.github.com:*"]

[seccomp]
allowed_syscalls = ["ptrace"] # Optional extra syscalls

[spoofs]
"config/secrets.json" = "{\"key\": \"mocked_value\"}"
```

---

## Performance

Astraea is designed for high-throughput environments. Current benchmarks show an average overhead of **~0.03ms** per intercepted call, well within the requirements for high-performance Node.js applications.

---

## Security Disclaimer

Astraea is a security research project. While it provides strong protection at the `libuv` layer, it does not currently prevent direct `syscall` invocations if a malicious module loads its own native binary. Future versions will address this via Seccomp integration.
