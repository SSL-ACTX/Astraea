use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Deserialize, Debug)]
struct AuditEvent {
    package: String,
    action: String,
    target: String,
    // allowed: bool, // We ignore 'allowed' for manifest generation as we want to include what was tried
}

#[derive(Serialize, Default)]
struct PackagePolicy {
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    fs: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    native_addons: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    network: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    env: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    proc: BTreeSet<String>,
}

#[derive(Serialize)]
struct Manifest {
    packages: BTreeMap<String, PackagePolicy>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: astraea-gen <audit_log_file>");
        std::process::exit(1);
    }

    let file = File::open(&args[1]).expect("Failed to open audit log");
    let reader = BufReader::new(file);

    let mut packages: BTreeMap<String, PackagePolicy> = BTreeMap::new();

    for line_str in reader.lines().map_while(Result::ok) {
        if let Ok(event) = serde_json::from_str::<AuditEvent>(&line_str) {
            let policy = packages.entry(event.package).or_default();
            match event.action.as_str() {
                "fs" => {
                    policy.fs.insert(event.target);
                }
                "native_addons" => {
                    policy.native_addons.insert(event.target);
                }
                "network" => {
                    policy.network.insert(event.target);
                }
                "env" => {
                    policy.env.insert(event.target);
                }
                "proc" => {
                    policy.proc.insert(event.target);
                }
                _ => {}
            }
        }
    }

    let manifest = Manifest { packages };
    let toml_str = toml::to_string_pretty(&manifest).expect("Failed to generate TOML");
    println!("{}", toml_str);
}
