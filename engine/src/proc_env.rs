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

        let normalized_binary = normalize_path(binary);

        let rules = match self.package_rules.get(package_name) {
            Some(r) => r,
            None => return false,
        };

        for pattern in &rules.allowed_proc {
            let normalized_pattern = if pattern.contains('*') {
                pattern.to_string()
            } else {
                normalize_path(pattern)
            };

            if self.match_pattern(&normalized_pattern, &normalized_binary) {
                debug!(target: "astraea", "ALLOW PROC: package '{}' -> '{}' (normalized: '{}')", package_name, binary, normalized_binary);
                return true;
            }
        }

        warn!(target: "astraea", "DENY PROC: package '{}' -> '{}' (normalized: '{}')", package_name, binary, normalized_binary);
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

fn normalize_path(path_str: &str) -> String {
    let path = std::path::Path::new(path_str);
    let mut components: Vec<String> = Vec::new();
    let is_absolute = path.is_absolute();

    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if let Some(last) = components.last() {
                    if last == ".." {
                        components.push("..".to_string());
                    } else {
                        components.pop();
                    }
                } else if !is_absolute {
                    components.push("..".to_string());
                }
            }
            std::path::Component::Normal(c) => {
                components.push(c.to_string_lossy().to_string());
            }
            std::path::Component::RootDir => {}
            std::path::Component::CurDir => {}
            _ => {}
        }
    }

    let mut res = if is_absolute {
        "/".to_string()
    } else {
        "".to_string()
    };
    res.push_str(&components.join("/"));

    if res.is_empty() {
        return ".".to_string();
    }
    res
}
