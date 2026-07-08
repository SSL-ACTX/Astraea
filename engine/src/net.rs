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

#[derive(Debug, PartialEq, Eq)]
pub enum NetAction {
    Connect,
    Bind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NetProtocol {
    Any,
    Tcp,
    Udp,
}

#[derive(Debug)]
struct PortPattern {
    ranges: Vec<(u16, u16)>,
}

impl PortPattern {
    fn parse(pattern: &str) -> Self {
        if pattern == "*" {
            return PortPattern {
                ranges: vec![(0, 65535)],
            };
        }
        let mut ranges = Vec::new();
        for part in pattern.split(',') {
            if let Some((start, end)) = part.split_once('-') {
                if let (Ok(s), Ok(e)) = (start.parse(), end.parse()) {
                    ranges.push((s, e));
                }
            } else if let Ok(p) = part.parse() {
                ranges.push((p, p));
            }
        }
        PortPattern { ranges }
    }

    fn matches(&self, port: u16) -> bool {
        self.ranges.iter().any(|(s, e)| port >= *s && port <= *e)
    }
}

#[derive(Debug)]
enum NetTarget {
    Ip(IpNet),
    Domain(String),
}

#[derive(Debug)]
struct NetRule {
    action: NetAction,
    protocol: NetProtocol,
    target: NetTarget,
    port_pattern: PortPattern,
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
                // Support old syntax "allow:host:port" as connect:*:host:port
                let parts: Vec<&str> = rule_str.split(':').collect();

                let action_str;
                let protocol_str;
                let host_str;
                let port_str;

                if parts.len() == 4 {
                    action_str = parts[0];
                    protocol_str = parts[1];
                    host_str = parts[2];
                    port_str = parts[3];
                } else if parts.len() == 3 && parts[0] == "allow" {
                    action_str = "connect";
                    protocol_str = "*";
                    host_str = parts[1];
                    port_str = parts[2];
                } else {
                    continue; // Invalid syntax
                }

                let action = match action_str {
                    "bind" => NetAction::Bind,
                    "connect" => NetAction::Connect,
                    _ => continue,
                };

                let protocol = match protocol_str {
                    "tcp" => NetProtocol::Tcp,
                    "udp" => NetProtocol::Udp,
                    "*" | "any" => NetProtocol::Any,
                    _ => continue,
                };

                let port_pattern = PortPattern::parse(port_str);

                let target = if host_str == "*" {
                    NetTarget::Ip(IpNet::from_str("0.0.0.0/0").unwrap())
                } else if let Ok(net) = IpNet::from_str(host_str) {
                    NetTarget::Ip(net)
                } else if let Ok(ip) = IpAddr::from_str(host_str) {
                    NetTarget::Ip(IpNet::from(ip))
                } else {
                    NetTarget::Domain(host_str.to_string())
                };

                rules.push(NetRule {
                    action,
                    protocol,
                    target,
                    port_pattern,
                });
            }
            package_rules.insert(name, rules);
        }

        NetManager {
            package_rules,
            dns_cache: DashMap::new(),
        }
    }

    pub fn register_dns(&self, package: &str, domain: &str, ips: Vec<String>, ttl: u32) {
        let ttl_secs = std::cmp::max(5, std::cmp::min(3600, ttl)) as u64;
        let expiry = std::time::Instant::now() + std::time::Duration::from_secs(ttl_secs);
        for ip_str in ips {
            let entry = DnsEntry {
                domain: domain.to_string(),
                package: package.to_string(),
                expiry,
            };
            self.dns_cache.entry(ip_str).or_default().push(entry);
        }
    }

    pub fn is_allowed(
        &self,
        package_name: &str,
        host_or_ip: &str,
        port: u16,
        action_code: i32,
        protocol_code: i32,
    ) -> bool {
        let rules = match self.package_rules.get(package_name) {
            Some(r) => r,
            None => return package_name == "root",
        };

        let req_action = match action_code {
            1 => NetAction::Bind,
            _ => NetAction::Connect,
        };

        let req_protocol = match protocol_code {
            6 => NetProtocol::Tcp,
            17 => NetProtocol::Udp,
            _ => NetProtocol::Any,
        };

        // Perform evaluation against explicit IP and Domain policies defined in the manifest.
        for rule in rules {
            if rule.action != req_action {
                continue;
            }
            // If requested proto is specific and rule is specific but they differ, reject.
            if rule.protocol != NetProtocol::Any
                && req_protocol != NetProtocol::Any
                && rule.protocol != req_protocol
            {
                continue;
            }
            if !rule.port_pattern.matches(port) {
                continue;
            }

            match &rule.target {
                NetTarget::Ip(net) => {
                    if let Ok(addr) = IpAddr::from_str(host_or_ip) {
                        // "0.0.0.0/0" matching any IPv4
                        if net.contains(&addr)
                            || (net.addr() == IpAddr::from_str("0.0.0.0").unwrap()
                                && net.prefix_len() == 0)
                        {
                            debug!(target: "astraea", "ALLOW NET (IP): package '{}' -> '{}:{}' (action={:?}, proto={:?})", package_name, host_or_ip, port, req_action, req_protocol);
                            return true;
                        }
                    }
                }
                NetTarget::Domain(d_patt) => {
                    if self.match_domain(d_patt, host_or_ip) {
                        debug!(target: "astraea", "ALLOW NET (Domain): package '{}' -> '{}:{}' (action={:?}, proto={:?})", package_name, host_or_ip, port, req_action, req_protocol);
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
                            if rule.action != req_action {
                                continue;
                            }
                            if rule.protocol != NetProtocol::Any
                                && req_protocol != NetProtocol::Any
                                && rule.protocol != req_protocol
                            {
                                continue;
                            }
                            if !rule.port_pattern.matches(port) {
                                continue;
                            }

                            if let NetTarget::Domain(d_patt) = &rule.target {
                                if self.match_domain(d_patt, &entry.domain) {
                                    debug!(target: "astraea", "ALLOW NET (DNS-Cached): package '{}' -> '{}:{}' (via {})", package_name, host_or_ip, port, entry.domain);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // Heuristic verification for missed DNS events: attempt a fresh resolution of authorized domains.
            for rule in rules {
                if rule.action != req_action {
                    continue;
                }
                if rule.protocol != NetProtocol::Any
                    && req_protocol != NetProtocol::Any
                    && rule.protocol != req_protocol
                {
                    continue;
                }
                if !rule.port_pattern.matches(port) {
                    continue;
                }

                if let NetTarget::Domain(d_patt) = &rule.target {
                    if !d_patt.contains('*') {
                        use std::net::ToSocketAddrs;
                        let lookup_target = format!("{}:{}", d_patt, port);
                        if let Ok(addrs) = lookup_target.to_socket_addrs() {
                            for addr_res in addrs {
                                if addr_res.ip() == addr {
                                    debug!(target: "astraea", "ALLOW NET (Verified): package '{}' -> '{}:{}' matches allowed domain '{}'", package_name, host_or_ip, port, d_patt);
                                    self.register_dns(package_name, d_patt, vec![ip_key.clone()], 60);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        warn!(target: "astraea", "DENY NET: package '{}' -> '{}:{}' (action={:?}, proto={:?}) (no matching rule)", package_name, host_or_ip, port, req_action, req_protocol);
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
