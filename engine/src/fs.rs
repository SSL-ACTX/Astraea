use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info, warn};

pub struct FsManager {
    package_rules: HashMap<String, GlobSet>,
    spoofs: HashMap<String, String>,
    project_root: PathBuf,
}

impl FsManager {
    pub fn new(
        packages: HashMap<String, crate::PackagePolicy>,
        spoofs: HashMap<String, String>,
    ) -> Self {
        let project_root = std::env::var("ASTRAEA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        info!(target: "astraea", "FsManager: Project root set to {:?}", project_root);
        let mut package_rules = HashMap::new();

        for (name, policy) in packages {
            let mut builder = GlobSetBuilder::new();
            for rule in policy.fs {
                if let Some(path_pattern) = rule.strip_prefix("read:") {
                    // Convert relative patterns to absolute based on project root
                    let absolute_pattern = if path_pattern.starts_with('/') {
                        path_pattern.to_string()
                    } else {
                        // Ensure relative globs match correctly against absolute paths
                        let mut p = project_root.clone();
                        if path_pattern.starts_with("./") {
                            p.push(&path_pattern[2..]);
                        } else {
                            p.push(path_pattern);
                        }
                        p.to_string_lossy().to_string()
                    };

                    debug!(target: "astraea", "LOAD FS RULE: {} -> {}", rule, absolute_pattern);

                    if let Ok(glob) = Glob::new(&absolute_pattern) {
                        builder.add(glob);
                    }
                }
            }
            if let Ok(set) = builder.build() {
                package_rules.insert(name, set);
            }
        }

        FsManager {
            package_rules,
            spoofs,
            project_root,
        }
    }

    pub fn is_allowed(&self, package_name: &str, requested_path: &str) -> bool {
        let path = PathBuf::from(requested_path);
        let absolute_path = if path.is_absolute() {
            path.clone()
        } else {
            self.project_root.join(&path)
        };

        // Normalize for system path checks
        let normalized = self.normalize_path(&absolute_path);

        // System Paths - Always Allow
        if normalized.starts_with("/data/data/com.termux/files/usr/etc/")
            || normalized.starts_with("/proc/")
            || normalized.starts_with("/sys/")
            || normalized.starts_with("/dev/")
            || normalized == "/etc/hosts"
            || normalized == "/etc/resolv.conf"
            || normalized.starts_with("/data/data/com.termux/files/usr/lib/")
            || normalized.starts_with("/usr/lib/")
            || normalized.starts_with("/usr/share/")
            || normalized.starts_with("/lib/")
            || normalized.starts_with("/lib64/")
            || normalized.starts_with("/etc/ssl/")
            || normalized.starts_with("/etc/pki/")
        // Node/System libraries
        {
            return true;
        }

        // Get relative path from project root for matching
        let relative_path = if let Ok(rel) = absolute_path.strip_prefix(&self.project_root) {
            rel.to_string_lossy().to_string()
        } else if let (Ok(abs_can), Ok(root_can)) = (
            absolute_path.canonicalize(),
            self.project_root.canonicalize(),
        ) {
            if let Ok(rel) = abs_can.strip_prefix(&root_can) {
                rel.to_string_lossy().to_string()
            } else {
                normalized.clone()
            }
        } else {
            normalized.clone()
        };

        if let Some(set) = self.package_rules.get(package_name) {
            // Check normalized match (handles absolute rules in manifest)
            if set.is_match(&normalized) {
                debug!(target: "astraea", "ALLOW FS (Absolute): package '{}' -> '{}'", package_name, normalized);
                return true;
            }

            // Check relative match (handles tests/** style rules)
            if set.is_match(&relative_path) {
                debug!(target: "astraea", "ALLOW FS (Relative): package '{}' -> '{}'", package_name, relative_path);
                return true;
            }

            warn!(target: "astraea", "DENY FS: package '{}' -> '{}' (rel: '{}')", package_name, normalized, relative_path);
            false
        } else {
            // Allow root by default if no rules are defined
            let allowed = package_name == "root";
            if !allowed {
                warn!(target: "astraea", "DENY FS (No Rules): package '{}' -> '{}'", package_name, normalized);
            }
            allowed
        }
    }

    pub fn get_spoof(&self, path: &str) -> Option<String> {
        self.spoofs
            .get(path)
            .map(|_mock_data| format!(".astraea_spoof_{}", path.replace('/', "_")))
    }

    fn normalize_path(&self, path: &std::path::Path) -> String {
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
                std::path::Component::RootDir => {
                    // Do nothing for RootDir component itself, handled by is_absolute flag
                }
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
}
