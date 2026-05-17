# Astraea Architectural Specification & Roadmap

**Status:** Phase 5 (Finalized/Experimental)  
**Security Model:** Object-Capability (O-Cap) at C-ABI Boundary  
**Technical Stack:** Rust (Engine), Zig (Interceptor), V8 (Introspection)

---

## 1. Executive Summary
Astraea is a high-performance security middleware engineered to enforce **mathematical zero-trust constraints** on Node.js applications. By operating at the native C-ABI boundary between the V8 engine and the host operating system, Astraea neutralizes supply-chain attacks, Remote Code Execution (RCE), and unauthorized data exfiltration. Unlike traditional JavaScript-based security tools, Astraea cannot be bypassed by obfuscation or runtime monkey-patching.

---

## 2. Technical Architecture

### 2.1 The Interceptor (Zig Layer)
The entry point of the system. It utilizes dynamic linker hijacking (`LD_PRELOAD`) to intercept critical system calls before they reach the kernel or `libuv`.
*   **Mechanism:** Exports symbols matching `libc` (`open`, `openat`) and `libuv` signatures.
*   **Optimization:** Uses Zig's `@cImport` for zero-cost header integration and `RTLD_NEXT` for transparent pass-through of allowed calls.
*   **Safety:** Implements a recursion guard to prevent the security engine from intercepting its own I/O.

### 2.2 The Attribution Engine (V8/Rust Layer)
The "context-aware" component that bridges the gap between a raw native call and the JavaScript module that initiated it.
*   **Dynamic Discovery:** Utilizes a build-time introspection script (`nm`-based) to resolve V8 internal mangled symbols at compile-time, ensuring cross-version compatibility.
*   **Stack Walking:** Pauses execution to walk the V8 isolate stack, identifying the first non-internal JavaScript frame.
*   **Sticky Context:** Implements a thread-local heuristic to propagate security context across asynchronous boundaries and worker threads.

### 2.3 The Capability Engine (Rust Layer)
A high-performance policy evaluator designed for minimal impact on the Node.js event loop.
*   **Data Structure:** Uses a **Radix Tree (Trie)** for $O(K)$ path resolution (where $K$ is path length), independent of rule count.
*   **Evaluation:** Validates $(Module, Action, Target)$ tuples against a compiled manifest.
*   **Performance:** Introduces ~36µs of overhead per intercepted call in `ReleaseFast` builds.

---

## 3. Implementation Roadmap

### Phase 1: Foundation & Interception [COMPLETE]
*   [x] Native C-ABI structure mirroring for `libuv` and `Bionic/Glibc`.
*   [x] Implementation of `LD_PRELOAD` hooks for `open` and `openat`.
*   [x] Zig/Rust FFI bridge for cross-language telemetry.

### Phase 2: Contextual Attribution [COMPLETE]
*   [x] V8 internal symbol mapping for `StackTrace` and `Isolate`.
*   [x] **Smart Symbol Discovery:** Automated discovery of C++ mangled names during build.
*   [x] Package-level attribution (mapping file paths to `node_modules` logical names).

### Phase 3: Capability Enforcement [COMPLETE]
*   [x] **Radix Tree Integration:** Blazing fast filesystem permission checks.
*   [x] **Manifest Standard:** TOML-based capability definition.
*   [x] **Mock Spoofing:** Redirection of unauthorized I/O to synthetic mock data.

### Phase 4: Hardening & Validation [COMPLETE]
*   [x] **Zero-Allocation Optimization:** Minimal heap usage during the critical path.
*   [x] **Clippy Compliance:** Strict adherence to Rust engineering standards.
*   [x] **Formal Benchmarking:** Documented performance profile (~36µs overhead).

### Phase 5: Native Bypass Mitigation [COMPLETE]
*   [x] **Seccomp-BPF Integration:** Strict syscall whitelist to prevent direct kernel escapes.
*   [x] **dlopen Interception:** Granular control over native addon loading per package.
*   [x] **Architecture Hardening:** Dedicated `guardian` module for low-level process security.

---

## 4. Security Considerations
*   **Native Bypasses:** Malicious modules using custom native addons to invoke direct `syscalls` (e.g., via `asm`). 
    *   *Mitigation:* Astraea restricts `dlopen` calls and enforces a Linux `seccomp-bpf` filter to block unauthorized syscalls at the kernel level.
*   **Path Normalization:** Astraea performs in-place path normalization to prevent bypasses via `../` traversal or redundant slashes.

---

## 5. Metadata & Licensing
*   **License:** GNU AGPL 3.0
*   **Version:** 0.1.0-experimental
*   **Author:** Seuriin
