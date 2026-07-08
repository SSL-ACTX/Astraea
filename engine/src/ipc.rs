use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum IpcRequest {
    EvaluateFs {
        package: String,
        path: String,
    },
    EvaluateDlopen {
        package: String,
        path: String,
    },
    EvaluateNet {
        package: String,
        host: String,
        port: u16,
        action: i32,
        protocol: i32,
    },
    EvaluateEnv {
        package: String,
        key: String,
    },
    EvaluateProc {
        package: String,
        binary: String,
    },
    RegisterDns {
        package: String,
        domain: String,
        ip: String,
        ttl: u32,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum IpcResponse {
    Decision(i32),
    DecisionWithRedirect {
        decision: i32,
        redirect_path: Option<String>,
    },
    Ack,
}
