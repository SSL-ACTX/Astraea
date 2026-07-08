use libc::c_char;

pub const DECISION_DENY: i32 = 0;
pub const DECISION_ALLOW: i32 = 1;
pub const DECISION_SPOOF: i32 = 2;

#[repr(C)]
pub struct EvaluationResult {
    pub decision: i32,
    pub redirect_path: *mut c_char,
}

pub trait Evaluator: Send + Sync {
    fn evaluate_fs(&self, package: &str, path: &str) -> (i32, Option<String>);
    fn evaluate_dlopen(&self, package: &str, path: &str) -> i32;
    fn evaluate_net(&self, package: &str, host: &str, port: u16, action: i32, protocol: i32)
        -> i32;
    fn evaluate_env(&self, package: &str, key: &str) -> i32;
    fn evaluate_proc(&self, package: &str, binary: &str) -> i32;
    fn register_dns(&self, package: &str, domain: &str, ip: &str, ttl: u32);
}

pub mod local;
pub mod remote;
