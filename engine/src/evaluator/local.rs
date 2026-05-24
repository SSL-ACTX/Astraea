use crate::audit::{AuditEvent, AuditLogger};
use crate::evaluator::{Evaluator, DECISION_ALLOW, DECISION_DENY, DECISION_SPOOF};
use crate::fs::FsManager;
use crate::net::NetManager;
use crate::proc_env::ProcEnvManager;
use crate::{Manifest, SeccompConfig};
use std::collections::HashMap;
use tracing::{debug, info, warn};

pub struct LocalEvaluator {
    fs: FsManager,
    net: NetManager,
    proc_env: ProcEnvManager,
    native_addon_rules: HashMap<String, Vec<String>>,
    pub seccomp: SeccompConfig,
    audit: Option<AuditLogger>,
}

impl LocalEvaluator {
    pub fn new(manifest: Manifest, audit: Option<AuditLogger>) -> Self {
        let mut native_addon_rules = HashMap::new();
        for (name, policy) in &manifest.packages {
            native_addon_rules.insert(name.clone(), policy.native_addons.clone());
        }

        LocalEvaluator {
            fs: FsManager::new(manifest.packages.clone(), manifest.spoofs),
            net: NetManager::new(manifest.packages.clone()),
            proc_env: ProcEnvManager::new(manifest.packages),
            native_addon_rules,
            seccomp: manifest.seccomp,
            audit,
        }
    }

    fn log_event(&self, package: &str, action: &str, target: &str, allowed: bool) {
        if let Some(audit) = &self.audit {
            audit.log(AuditEvent {
                package: package.to_string(),
                action: action.to_string(),
                target: target.to_string(),
                allowed,
            });
        }
    }
}

impl Evaluator for LocalEvaluator {
    fn evaluate_fs(&self, package: &str, path: &str) -> (i32, Option<String>) {
        if let Some(spoof_path) = self.fs.get_spoof(path) {
            info!(target: "astraea", "SPOOF: package '{}' -> '{}' (redirected to mock)", package, path);
            self.log_event(package, "fs", &format!("spoof:{}", path), true);
            return (DECISION_SPOOF, Some(spoof_path));
        }

        if self.fs.is_allowed(package, path) {
            self.log_event(package, "fs", &format!("read:{}", path), true);
            (DECISION_ALLOW, None)
        } else {
            self.log_event(package, "fs", &format!("read:{}", path), false);
            (DECISION_DENY, None)
        }
    }

    fn evaluate_dlopen(&self, package: &str, path: &str) -> i32 {
        let is_addon = path.ends_with(".node");

        let allowed = if !is_addon {
            true
        } else if let Some(allowed_addons) = self.native_addon_rules.get(package) {
            allowed_addons
                .iter()
                .any(|a| path.ends_with(a) || (a == "*.node"))
        } else {
            package == "root"
        };

        if is_addon {
            self.log_event(package, "native_addons", path, allowed);
        }

        if !allowed {
            warn!(target: "astraea", "DENY DLOPEN: package '{}' -> '{}' (unauthorized native addon)", package, path);
            DECISION_DENY
        } else {
            debug!(target: "astraea", "ALLOW DLOPEN: package '{}' -> '{}'", package, path);
            DECISION_ALLOW
        }
    }

    fn evaluate_net(
        &self,
        package: &str,
        host: &str,
        port: u16,
        action: i32,
        protocol: i32,
    ) -> i32 {
        let allowed = self.net.is_allowed(package, host, port, action, protocol);

        let action_str = match action {
            1 => "bind",
            _ => "connect",
        };

        let proto_str = match protocol {
            6 => "tcp",
            17 => "udp",
            _ => "any",
        };

        self.log_event(
            package,
            "network",
            &format!("{}:{}:{}:{}", action_str, proto_str, host, port),
            allowed,
        );

        if allowed {
            DECISION_ALLOW
        } else {
            DECISION_DENY
        }
    }

    fn evaluate_env(&self, package: &str, key: &str) -> i32 {
        let allowed = self.proc_env.is_env_allowed(package, key);
        self.log_event(package, "env", key, allowed);
        if allowed {
            DECISION_ALLOW
        } else {
            DECISION_DENY
        }
    }

    fn evaluate_proc(&self, package: &str, binary: &str) -> i32 {
        let allowed = self.proc_env.is_proc_allowed(package, binary);
        self.log_event(package, "proc", binary, allowed);
        if allowed {
            DECISION_ALLOW
        } else {
            DECISION_DENY
        }
    }

    fn register_dns(&self, package: &str, domain: &str, ip: &str) {
        debug!(target: "astraea", "DNS CACHE: package '{}' resolved '{}' -> '{}'", package, domain, ip);
        self.net.register_dns(package, domain, vec![ip.to_string()]);
    }
}
