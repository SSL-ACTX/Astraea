use crate::evaluator::{Evaluator, DECISION_ALLOW};
use crate::ipc::{IpcRequest, IpcResponse};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

pub struct RemoteEvaluator {
    socket_path: String,
}

impl RemoteEvaluator {
    pub fn new(socket_path: &str) -> Self {
        RemoteEvaluator {
            socket_path: socket_path.to_string(),
        }
    }

    fn send_request(&self, request: IpcRequest) -> Option<IpcResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).ok().or_else(|| {
            tracing::error!(
                "RemoteEvaluator: Failed to connect to daemon at {}",
                self.socket_path
            );
            None
        })?;

        let request_bytes = serde_json::to_vec(&request).ok()?;
        let len = request_bytes.len() as u32;
        stream.write_all(&len.to_be_bytes()).ok()?;
        stream.write_all(&request_bytes).ok()?;

        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).ok()?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        let mut response_bytes = vec![0u8; len];
        stream.read_exact(&mut response_bytes).ok()?;

        let response: IpcResponse = serde_json::from_slice(&response_bytes).ok()?;
        tracing::debug!("RemoteEvaluator: Received response {:?}", response);
        Some(response)
    }
}

impl Evaluator for RemoteEvaluator {
    fn evaluate_fs(&self, package: &str, path: &str) -> (i32, Option<String>) {
        let req = IpcRequest::EvaluateFs {
            package: package.to_string(),
            path: path.to_string(),
        };
        match self.send_request(req) {
            Some(IpcResponse::DecisionWithRedirect {
                decision,
                redirect_path,
            }) => (decision, redirect_path),
            Some(IpcResponse::Decision(decision)) => (decision, None),
            _ => (DECISION_ALLOW, None),
        }
    }

    fn evaluate_dlopen(&self, package: &str, path: &str) -> i32 {
        let req = IpcRequest::EvaluateDlopen {
            package: package.to_string(),
            path: path.to_string(),
        };
        if let Some(IpcResponse::Decision(decision)) = self.send_request(req) {
            decision
        } else {
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
        let req = IpcRequest::EvaluateNet {
            package: package.to_string(),
            host: host.to_string(),
            port,
            action,
            protocol,
        };
        if let Some(IpcResponse::Decision(decision)) = self.send_request(req) {
            decision
        } else {
            DECISION_ALLOW
        }
    }

    fn evaluate_env(&self, package: &str, key: &str) -> i32 {
        let req = IpcRequest::EvaluateEnv {
            package: package.to_string(),
            key: key.to_string(),
        };
        if let Some(IpcResponse::Decision(decision)) = self.send_request(req) {
            decision
        } else {
            DECISION_ALLOW
        }
    }

    fn evaluate_proc(&self, package: &str, binary: &str) -> i32 {
        let req = IpcRequest::EvaluateProc {
            package: package.to_string(),
            binary: binary.to_string(),
        };
        if let Some(IpcResponse::Decision(decision)) = self.send_request(req) {
            decision
        } else {
            DECISION_ALLOW
        }
    }

    fn register_dns(&self, package: &str, domain: &str, ip: &str) {
        let req = IpcRequest::RegisterDns {
            package: package.to_string(),
            domain: domain.to_string(),
            ip: ip.to_string(),
        };
        let _ = self.send_request(req);
    }
}
