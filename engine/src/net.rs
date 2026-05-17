use dashmap::DashMap;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{debug, warn};

pub struct NetManager {
    package_rules: HashMap<String, Vec<NetRule>>,
    dns_cache: DashMap<String, Vec<DnsEntry>>, // IP -> [ (Domain, Package) ]
}

#[derive(Debug)]
enum NetRule {
    Ip(IpNet, String),      // CIDR, Port Pattern ("*" or numeric)
    Domain(String, String), // Host Pattern, Port Pattern
}

#[derive(Debug)]
struct DnsEntry {
    domain: String,
    package: String,
    expiry: std::time::Instant,
}

impl NetManager {
    pub fn new(packages: HashMap<String, crate::PackagePolicy>) -> Self {
        let mut package_rules = HashMap::new();

        for (name, policy) in packages {
            let mut rules = Vec::new();
            for rule_str in policy.network {
                if let Some(pattern) = rule_str.strip_prefix("allow:") {
                    let parts: Vec<&str> = pattern.split(':').collect();
                    if parts.len() == 2 {
                        let host_or_cidr = parts[0];
                        let port = parts[1].to_string();

                        if let Ok(net) = IpNet::from_str(host_or_cidr) {
                            rules.push(NetRule::Ip(net, port));
                        } else if let Ok(ip) = IpAddr::from_str(host_or_cidr) {
                            let net = IpNet::from(ip);
                            rules.push(NetRule::Ip(net, port));
                        } else {
                            rules.push(NetRule::Domain(host_or_cidr.to_string(), port));
                        }
                    }
                }
            }
            package_rules.insert(name, rules);
        }

        NetManager {
            package_rules,
            dns_cache: DashMap::new(),
        }
    }

    pub fn register_dns(&self, package: &str, domain: &str, ips: Vec<String>) {
        let expiry = std::time::Instant::now() + std::time::Duration::from_secs(60);
        for ip_str in ips {
            let entry = DnsEntry {
                domain: domain.to_string(),
                package: package.to_string(),
                expiry,
            };
            self.dns_cache.entry(ip_str).or_default().push(entry);
        }
    }

    pub fn is_allowed(&self, package_name: &str, host_or_ip: &str, port: u16) -> bool {
        let rules = match self.package_rules.get(package_name) {
            Some(r) => r,
            None => return package_name == "root",
        };

        let port_str = port.to_string();

        // Perform evaluation against explicit IP and Domain policies defined in the manifest.
        for rule in rules {
            match rule {
                NetRule::Ip(net, p_patt) => {
                    if let Ok(addr) = IpAddr::from_str(host_or_ip) {
                        if net.contains(&addr) && (p_patt == "*" || p_patt == &port_str) {
                            debug!(target: "astraea", "ALLOW NET (IP): package '{}' -> '{}:{}'", package_name, host_or_ip, port);
                            return true;
                        }
                    }
                }
                NetRule::Domain(d_patt, p_patt) => {
                    if self.match_domain(d_patt, host_or_ip)
                        && (p_patt == "*" || p_patt == &port_str)
                    {
                        debug!(target: "astraea", "ALLOW NET (Domain): package '{}' -> '{}:{}'", package_name, host_or_ip, port);
                        return true;
                    }
                }
            }
        }

        // Consult the DNS cache to verify if the raw IP corresponds to a previously authorized domain resolution.
        if let Ok(addr) = IpAddr::from_str(host_or_ip) {
            let ip_key = addr.to_string();
            if let Some(entries) = self.dns_cache.get(&ip_key) {
                let now = std::time::Instant::now();
                for entry in entries.iter() {
                    if entry.expiry > now && entry.package == package_name {
                        for rule in rules {
                            if let NetRule::Domain(d_patt, p_patt) = rule {
                                if self.match_domain(d_patt, &entry.domain)
                                    && (p_patt == "*" || p_patt == &port_str)
                                {
                                    debug!(target: "astraea", "ALLOW NET (DNS-Cached): package '{}' -> '{}:{}' (via {})", package_name, host_or_ip, port, entry.domain);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // Heuristic verification for missed DNS events: attempt a fresh resolution of authorized domains.
            // This fallback handles scenarios where Node.js lookups bypass Astraea's primary interceptors.
            for rule in rules {
                if let NetRule::Domain(d_patt, p_patt) = rule {
                    if p_patt == "*" || p_patt == &port_str {
                        // Resolve the pattern if it's not a wildcard
                        if !d_patt.contains('*') {
                            use std::net::ToSocketAddrs;
                            let lookup_target = format!("{}:{}", d_patt, port);
                            if let Ok(addrs) = lookup_target.to_socket_addrs() {
                                for addr_res in addrs {
                                    if addr_res.ip() == addr {
                                        debug!(target: "astraea", "ALLOW NET (Verified): package '{}' -> '{}:{}' matches allowed domain '{}'", package_name, host_or_ip, port, d_patt);
                                        // Cache it for next time
                                        self.register_dns(
                                            package_name,
                                            d_patt,
                                            vec![ip_key.clone()],
                                        );
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        warn!(target: "astraea", "DENY NET: package '{}' -> '{}:{}' (no matching rule)", package_name, host_or_ip, port);
        false
    }

    fn match_domain(&self, pattern: &str, domain: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // ".github.com"
            domain.ends_with(suffix)
        } else {
            pattern == domain
        }
    }
}
