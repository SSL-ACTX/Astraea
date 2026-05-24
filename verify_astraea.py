import subprocess
import os
import time
import signal
import json
import socket
import threading

def run_daemon():
    print("--- Starting Astraea Daemon ---")
    env = os.environ.copy()
    env["ASTRAEA_ROOT"] = os.getcwd()
    env["ASTRAEA_CONFIG"] = os.path.join(os.getcwd(), "astraea.toml")
    # We use cargo run to ensure it's built and running the latest code
    daemon_proc = subprocess.Popen(
        ["cargo", "run", "--bin", "astraea-daemon"],
        cwd="engine",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
        preexec_fn=os.setsid
    )
    return daemon_proc

def tail_telemetry(socket_path, events_list):
    if os.path.exists(socket_path):
        os.remove(socket_path)
    
    # The daemon creates the socket, so we wait for it
    max_retries = 10
    while not os.path.exists(socket_path) and max_retries > 0:
        time.sleep(0.5)
        max_retries -= 1
    
    if not os.path.exists(socket_path):
        print(f"Error: Telemetry socket {socket_path} not created by daemon")
        return

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(socket_path)
            s.settimeout(1.0)
            while True:
                try:
                    data = s.recv(1024)
                    if not data:
                        break
                    for line in data.decode().splitlines():
                        if line.strip():
                            events_list.append(json.loads(line))
                except socket.timeout:
                    continue
                except Exception:
                    break
    except Exception as e:
        print(f"Telemetry collector error: {e}")

def run_test(test_file, telemetry_socket):
    print(f"--- Running Test: {test_file} ---")
    env = os.environ.copy()
    env["ASTRAEA_DAEMON"] = "1"
    env["ASTRAEA_TELEMETRY"] = telemetry_socket
    env["LD_PRELOAD"] = os.path.abspath("zig-out/lib/libastraea.so")
    env["RUST_LOG"] = "astraea=debug,engine=debug"
    
    try:
        result = subprocess.run(
            ["node", test_file],
            env=env,
            capture_output=True,
            text=True,
            timeout=20
        )
        print(result.stdout)
        print(result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"Test {test_file} timed out")
        return False

def main():
    telemetry_socket = "/data/data/com.termux/files/home/.gemini/tmp/astraea/astraea.telemetry.sock"
    # The daemon creates it at /data/data/com.termux/files/home/.gemini/tmp/astraea/astraea.telemetry.sock usually based on temp_dir
    # But wait, our code uses std::env::temp_dir(). Let's find out where that is.
    temp_dir = os.environ.get("TMPDIR", "/tmp")
    telemetry_socket = os.path.join(temp_dir, "astraea.telemetry.sock")
    
    daemon_proc = run_daemon()
    time.sleep(2) # Wait for daemon to initialize
    
    test_suites = [
        "tests/suite/fs.test.js",
        "tests/suite/net.test.js",
        "tests/suite/native.test.js"
    ]
    
    all_passed = True
    for suite in test_suites:
        if not run_test(suite, telemetry_socket):
            all_passed = False
    
    # Cleanup
    os.killpg(os.getpgid(daemon_proc.pid), signal.SIGTERM)
    
    if all_passed:
        print("\n✅ VERIFICATION SUCCESSFUL")
    else:
        print("\n❌ VERIFICATION FAILED")
        exit(1)

if __name__ == "__main__":
    main()
