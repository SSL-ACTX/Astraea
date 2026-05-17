use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, warn};

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
        let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut package_rules = HashMap::new();

        for (name, policy) in packages {
            let mut builder = GlobSetBuilder::new();
            for rule in policy.fs {
                if let Some(path_pattern) = rule.strip_prefix("read:") {
                    // Convert relative patterns to absolute based on project root
                    let absolute_pattern = if path_pattern.starts_with('/') {
                        path_pattern.to_string()
                    } else {
                        project_root
                            .join(path_pattern)
                            .to_string_lossy()
                            .to_string()
                    };

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
        // Always allow system paths
        if requested_path.starts_with("/data/data/com.termux/files/usr/etc/")
            || requested_path.starts_with("/proc/")
            || requested_path.starts_with("/sys/")
            || requested_path.starts_with("/dev/")
            || requested_path == "/etc/hosts"
            || requested_path == "/etc/resolv.conf"
        {
            return true;
        }

        let path = PathBuf::from(requested_path);
        let absolute_path = if path.is_absolute() {
            path
        } else {
            self.project_root.join(path)
        };

        // Normalize the path (remove .. and .)
        let normalized = self.normalize_path(&absolute_path);

        if let Some(set) = self.package_rules.get(package_name) {
            let allowed = set.is_match(&normalized);
            if !allowed {
                warn!(target: "astraea", "DENY FS: package '{}' -> '{}' (no matching rule)", package_name, normalized);
            } else {
                debug!(target: "astraea", "ALLOW FS: package '{}' -> '{}'", package_name, normalized);
            }
            allowed
        } else {
            let allowed = package_name == "root";
            if allowed {
                debug!(target: "astraea", "ALLOW FS (Default): package '{}' -> '{}'", package_name, normalized);
            } else {
                warn!(target: "astraea", "DENY FS (Default): package '{}' -> '{}'", package_name, normalized);
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
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    components.pop();
                }
                std::path::Component::Normal(c) => {
                    components.push(c);
                }
                std::path::Component::RootDir => {
                    components.clear();
                    components.push(std::ffi::OsStr::new("/"));
                }
                _ => {}
            }
        }

        let mut res = PathBuf::new();
        for (i, c) in components.iter().enumerate() {
            if i == 0 && c == &std::ffi::OsStr::new("/") {
                res.push("/");
            } else {
                res.push(c);
            }
        }
        res.to_string_lossy().to_string()
    }
}
