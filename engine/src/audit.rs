use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc::{channel, Sender};
use std::thread;

#[derive(Serialize, Debug)]
pub struct AuditEvent {
    pub package: String,
    pub action: String,
    pub target: String,
    pub allowed: bool,
}

pub struct AuditLogger {
    tx: Sender<AuditEvent>,
}

impl AuditLogger {
    pub fn new(path: &str) -> Option<Self> {
        let path = path.to_string();
        let (tx, rx) = channel::<AuditEvent>();

        let mut file = File::create(&path).ok()?;

        thread::spawn(move || {
            while let Ok(event) = rx.recv() {
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = writeln!(file, "{}", json);
                }
            }
            let _ = file.flush();
        });

        Some(AuditLogger { tx })
    }

    pub fn log(&self, event: AuditEvent) {
        let _ = self.tx.send(event);
    }
}
