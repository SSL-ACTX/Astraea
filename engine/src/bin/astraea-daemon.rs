use engine::audit::AuditLogger;
use engine::evaluator::local::LocalEvaluator;
use engine::evaluator::{Evaluator, DECISION_SPOOF};
use engine::ipc::{IpcRequest, IpcResponse};
use engine::{Manifest, SeccompConfig};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::FmtSubscriber;

fn handle_client(mut stream: UnixStream, evaluator: Arc<LocalEvaluator>) {
    info!("New client connected to daemon via IPC");
    loop {
        let mut len_bytes = [0u8; 4];
        if stream.read_exact(&mut len_bytes).is_err() {
            debug!("Client disconnected");
            break;
        }
        let len = u32::from_be_bytes(len_bytes) as usize;

        let mut request_bytes = vec![0u8; len];
        if stream.read_exact(&mut request_bytes).is_err() {
            break;
        }

        if let Ok(req) = serde_json::from_slice::<IpcRequest>(&request_bytes) {
            let res = match req {
                IpcRequest::EvaluateFs { package, path } => {
                    debug!("IPC Request: FsAccess {} -> {}", package, path);
                    let (decision, redirect_path) = evaluator.evaluate_fs(&package, &path);
                    if decision == DECISION_SPOOF {
                        IpcResponse::DecisionWithRedirect {
                            decision,
                            redirect_path,
                        }
                    } else {
                        IpcResponse::Decision(decision)
                    }
                }
                IpcRequest::EvaluateDlopen { package, path } => {
                    debug!("IPC Request: Dlopen {} -> {}", package, path);
                    IpcResponse::Decision(evaluator.evaluate_dlopen(&package, &path))
                }
                IpcRequest::EvaluateNet {
                    package,
                    host,
                    port,
                    action,
                    protocol,
                } => {
                    debug!("IPC Request: NetAccess {} -> {}:{}", package, host, port);
                    IpcResponse::Decision(
                        evaluator.evaluate_net(&package, &host, port, action, protocol),
                    )
                }
                IpcRequest::EvaluateEnv { package, key } => {
                    debug!("IPC Request: EnvAccess {} -> {}", package, key);
                    IpcResponse::Decision(evaluator.evaluate_env(&package, &key))
                }
                IpcRequest::EvaluateProc { package, binary } => {
                    debug!("IPC Request: ProcAccess {} -> {}", package, binary);
                    IpcResponse::Decision(evaluator.evaluate_proc(&package, &binary))
                }
                IpcRequest::RegisterDns {
                    package,
                    domain,
                    ip,
                    ttl,
                } => {
                    debug!(
                        "IPC Request: RegisterDns {} -> {} ({}) (ttl: {}s)",
                        package, domain, ip, ttl
                    );
                    evaluator.register_dns(&package, &domain, &ip, ttl);
                    IpcResponse::Ack
                }
            };

            if let Ok(res_bytes) = serde_json::to_vec(&res) {
                let res_len = res_bytes.len() as u32;
                if stream.write_all(&res_len.to_be_bytes()).is_err() {
                    break;
                }
                if stream.write_all(&res_bytes).is_err() {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn start_ipc_server(evaluator: Arc<LocalEvaluator>) -> std::io::Result<()> {
    let socket_path_buf = std::env::temp_dir().join("astraea.sock");
    let socket_path = socket_path_buf.to_str().unwrap();
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!("Astraea Daemon IPC listening on {}", socket_path);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let ev = Arc::clone(&evaluator);
                std::thread::spawn(move || {
                    handle_client(stream, ev);
                });
            }
            Err(err) => {
                error!("Connection failed: {}", err);
            }
        }
    }

    Ok(())
}

fn inject_library(pid: u32) {
    info!("Attempting to inject Astraea into PID {}", pid);

    // In a production environment, this would use raw ptrace shellcode injection.
    // For this prototype, we'll try to use a standard gdb-based injection wrapper
    // or log that dynamic injection was triggered.

    let lib_path = std::fs::canonicalize("./zig-out/lib/libastraea.so")
        .unwrap_or_else(|_| std::path::PathBuf::from("./zig-out/lib/libastraea.so"))
        .display()
        .to_string();

    debug!("Target library path: {}", lib_path);

    // Fallback: Notify user if running on Android/Termux where ptrace might be blocked by yama or selinux
    // without root.
    info!(
        "Ptrace Injection triggered for PID {}. (Note: requires CAP_SYS_PTRACE or root)",
        pid
    );

    let child = std::process::Command::new("gdb")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-batch")
        .arg("-ex")
        .arg(format!("call (void*)dlopen(\"{}\", 2)", lib_path))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    if let Ok(mut c) = child {
        let _ = c.wait();
        info!("Injection attempt finished for PID {}", pid);
    } else {
        error!("gdb not found or unable to run. Native ptrace shellcode injector required.");
    }
}

fn watch_and_inject() {
    let mut seen_pids = HashSet::new();
    info!("Starting Process Watcher...");

    loop {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let file_name = entry.file_name();
                        let pid_str = file_name.to_string_lossy();
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            if !seen_pids.contains(&pid) {
                                seen_pids.insert(pid);

                                let cmdline_path = entry.path().join("cmdline");
                                if let Ok(cmdline) = std::fs::read(cmdline_path) {
                                    // cmdline is null-separated
                                    if let Some(first_arg) = cmdline.split(|&b| b == 0).next() {
                                        let exe_name = String::from_utf8_lossy(first_arg);
                                        if exe_name.ends_with("node")
                                            || exe_name.ends_with("astraea-node")
                                        {
                                            inject_library(pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn handle_telemetry(stream: UnixStream) {
    let reader = std::io::BufReader::new(stream);
    use std::io::BufRead;
    for line in reader.lines() {
        if let Ok(l) = line {
            info!("TELEMETRY: {}", l);
        } else {
            break;
        }
    }
}

fn start_telemetry_server() -> std::io::Result<()> {
    let socket_path_buf = std::env::temp_dir().join("astraea.telemetry.sock");
    let socket_path = socket_path_buf.to_str().unwrap();
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!("Astraea Telemetry Server listening on {}", socket_path);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || {
                    handle_telemetry(stream);
                });
            }
            Err(err) => {
                error!("Telemetry connection failed: {}", err);
            }
        }
    }

    Ok(())
}

fn main() {
    let subscriber = FmtSubscriber::builder().with_env_filter("info").finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    info!("Starting Astraea Daemon...");

    let config_path =
        std::env::var("ASTRAEA_CONFIG").unwrap_or_else(|_| "astraea.toml".to_string());
    let manifest_str = std::fs::read_to_string(&config_path).unwrap_or_else(|_| {
        warn!(
            "Astraea Daemon: Config file not found at {}, using empty manifest.",
            config_path
        );
        String::new()
    });
    let manifest: Manifest = toml::from_str(&manifest_str).unwrap_or(Manifest {
        packages: HashMap::new(),
        spoofs: HashMap::new(),
        seccomp: SeccompConfig::default(),
    });

    let audit_path = std::env::var("ASTRAEA_AUDIT").ok();
    let audit = audit_path.map(|p| AuditLogger::new(engine::audit::AuditSink::File(p)));

    let evaluator = Arc::new(LocalEvaluator::new(manifest, audit));

    std::thread::spawn(|| {
        watch_and_inject();
    });

    std::thread::spawn(|| {
        if let Err(e) = start_telemetry_server() {
            error!("Telemetry Server Error: {}", e);
        }
    });

    if let Err(e) = start_ipc_server(evaluator) {
        error!("IPC Server Error: {}", e);
    }
}
