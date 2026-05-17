# Astraea (Experimental)

**Astraea** is a high-performance, zero-trust security middleware for Node.js. It implements an **Object-Capability (O-Cap)** enforcement layer at the native C-ABI boundary, protecting applications from supply-chain attacks, RCE exploits, and unauthorized data access.

> [!IMPORTANT] 
> Astraea is currently in active development. While functional, it is intended for security research and development environments.

---

## Key Features

*   **Native Interception:** Hooks `libuv` and `libc` file system calls (`open`, `openat`, etc.) using dynamic linker hijacking.
*   **Context-Aware Attribution:** Automatically correlates native I/O requests back to the specific JavaScript module/package that triggered them via V8 stack introspection.
*   **Smart Symbol Discovery:** Automatically discovers V8 internal symbols at compile-time by inspecting the local Node.js binary, ensuring compatibility across versions without fragile hardcoding.
*   **Sticky Context Heuristic:** Maintains security context across asynchronous boundaries and worker threads.
*   **Zero-Allocation Policy Engine:** Ultra-fast Radix Tree-based evaluation implemented in Rust for minimal latency (< 0.04ms overhead).
*   **Capability Spoofing:** Seamlessly redirects unauthorized access to synthetic mock data instead of failing, allowing applications to continue running safely.
*   **Centralized Observability:** Professional structured logging using the `tracing` ecosystem.

---

## Architecture

Astraea leverages a unique hybrid architecture to maximize performance and portability:

1.  **The Interceptor (Zig):** A lightweight C-ABI wrapper that hijacks system calls. Zig's `@cImport` provides seamless, zero-overhead access to `libuv` headers.
2.  **The Engine (Rust):** The "brain" of the system. It uses a custom build-time discovery script to link into V8's internal symbols, allowing it to perform deep stack introspection and evaluate policies against a high-performance Radix Tree.

---

## Documentation Index

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
fs = [
    "read:package.json",
    "read:src/**"      # Wildcard support via Radix Tree
]

[packages.axios]
fs = ["read:certs/**"]

[spoofs]
"config/secrets.json" = "{\"key\": \"mocked_value\"}"
```

---

## Performance

Astraea is designed for high-throughput environments. Current benchmarks show an average overhead of **~0.03ms** per intercepted call, well within the requirements for high-performance Node.js applications.

---

## Security Disclaimer

Astraea is a security research project. While it provides strong protection at the `libuv` layer, it does not currently prevent direct `syscall` invocations if a malicious module loads its own native binary. Future versions will address this via Seccomp integration.
