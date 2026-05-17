# Astraea v2 Roadmap: Beyond the Filesystem

This document outlines the strategic direction for Astraea as it evolves into a full-spectrum security mesh for Node.js.

---

## Phase 6: Network Capability Enforcement (DONE)
Currently, Astraea focuses on filesystem and native bypasses. Phase 6 extends this protection to the network stack.
*   **Intercepted Symbols:** `connect`, `sendto`, `recvfrom`, `getaddrinfo`.
*   **Capability Model:** `packages.<name>.network = ["allow:api.github.com:443", "deny:0.0.0.0/0"]`.
*   **FFI Extension:** `evaluate_net_access(addr, port, package_name)`.

## Phase 7: Process & Environment Control (DONE)
Restrict the ability of modules to influence the host environment or spawn child processes.
*   **Intercepted Symbols:** `execve`, `posix_spawn`, `setenv`, `putenv`.
*   **Goal:** Allow only the `root` package to spawn specific binaries or modify environment variables.

## Phase 8: Learning Mode (Auto-Manifest) (DONE)
Automatically generate security manifests based on empirical observation.
*   **Mechanism:** A passive "audit" mode that logs every $(Package, Action, Target)$ tuple to a JSON file.
*   **CLI Tool:** `astraea-gen manifest.json > astraea.toml`.

## Phase 9: Telemetry & Observability (CURRENT)
Integrate Astraea with production monitoring and incident response workflows.
*   **Mechanism:** Asynchronous event streaming via a dedicated background thread to a Unix Domain Socket or `statsd`.
*   **Data Points:** Blocked actions, unusual stack depths, and seccomp violations.
