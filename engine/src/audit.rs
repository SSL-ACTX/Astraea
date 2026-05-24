use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

#[derive(Serialize, Debug)]
pub struct AuditEvent {
    pub package: String,
    pub action: String,
    pub target: String,
    pub allowed: bool,
}

pub enum AuditSink {
    File(String),
    Uds(String),
}

pub struct AuditLogger {
    tx: Sender<AuditEvent>,
}

impl AuditLogger {
    pub fn new(sink: AuditSink) -> Self {
        let (tx, rx) = channel::<AuditEvent>();

        thread::spawn(move || {
            let mut current_sink: Option<Box<dyn Write + Send>> = match &sink {
                AuditSink::File(path) => File::create(path)
                    .ok()
                    .map(|f| Box::new(f) as Box<dyn Write + Send>),
                AuditSink::Uds(path) => UnixStream::connect(path)
                    .ok()
                    .map(|s| Box::new(s) as Box<dyn Write + Send>),
            };

            while let Ok(event) = rx.recv() {
                if let Ok(json) = serde_json::to_string(&event) {
                    let mut success = false;
                    if let Some(mut s) = current_sink.take() {
                        if writeln!(s, "{}", json).is_ok() && s.flush().is_ok() {
                            current_sink = Some(s);
                            success = true;
                        }
                    }

                    if !success {
                        // Attempt reconnection for UDS
                        if let AuditSink::Uds(path) = &sink {
                            for _ in 0..3 {
                                if let Ok(mut s) = UnixStream::connect(path) {
                                    if writeln!(s, "{}", json).is_ok() && s.flush().is_ok() {
                                        current_sink = Some(Box::new(s));
                                        break;
                                    }
                                }
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                }
            }
        });

        AuditLogger { tx }
    }

    pub fn log(&self, event: AuditEvent) {
        let _ = self.tx.send(event);
    }
}
