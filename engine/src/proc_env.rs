use std::collections::HashMap;
use tracing::{debug, warn};

pub struct ProcEnvManager {
    package_rules: HashMap<String, ProcEnvRules>,
}

struct ProcEnvRules {
    allowed_env: Vec<String>,  // Keys or patterns
    allowed_proc: Vec<String>, // Binary paths or patterns
}

impl ProcEnvManager {
    pub fn new(packages: HashMap<String, crate::PackagePolicy>) -> Self {
        let mut package_rules = HashMap::new();

        for (name, policy) in packages {
            package_rules.insert(
                name,
                ProcEnvRules {
                    allowed_env: policy.env,
                    allowed_proc: policy.proc,
                },
            );
        }

        ProcEnvManager { package_rules }
    }

    pub fn is_env_allowed(&self, package_name: &str, key: &str) -> bool {
        if package_name == "root" {
            return true;
        }

        let rules = match self.package_rules.get(package_name) {
            Some(r) => r,
            None => return false,
        };

        for pattern in &rules.allowed_env {
            if self.match_pattern(pattern, key) {
                debug!(target: "astraea", "ALLOW ENV: package '{}' -> '{}'", package_name, key);
                return true;
            }
        }

        warn!(target: "astraea", "DENY ENV: package '{}' -> '{}'", package_name, key);
        false
    }

    pub fn is_proc_allowed(&self, package_name: &str, binary: &str) -> bool {
        if package_name == "root" {
            return true;
        }

        let rules = match self.package_rules.get(package_name) {
            Some(r) => r,
            None => return false,
        };

        for pattern in &rules.allowed_proc {
            if self.match_pattern(pattern, binary) {
                debug!(target: "astraea", "ALLOW PROC: package '{}' -> '{}'", package_name, binary);
                return true;
            }
        }

        warn!(target: "astraea", "DENY PROC: package '{}' -> '{}'", package_name, binary);
        false
    }

    fn match_pattern(&self, pattern: &str, target: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return target.starts_with(prefix);
        }
        pattern == target
    }
}
