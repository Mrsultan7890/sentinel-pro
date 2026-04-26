/// Intercept engine — holds flows until UI decides FWD or DROP
///
/// Flow:
///   proxy.rs calls intercept_manager.hold(flow_id, flow_data)
///   → blocks until Python sends {action: "forward"/"drop"} via IPC
///   → returns true (forward) or false (drop)

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct InterceptManager {
    pending:      Arc<DashMap<String, oneshot::Sender<InterceptAction>>>,
    enabled:      Arc<std::sync::atomic::AtomicBool>,
    scope_filter: Arc<std::sync::RwLock<Vec<String>>>,  // empty = intercept all
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterceptAction {
    Forward,
    Drop,
    ForwardModified { headers: Vec<(String, String)>, body: Vec<u8> },
}

impl InterceptManager {
    pub fn new() -> Self {
        Self {
            pending:      Arc::new(DashMap::new()),
            enabled:      Arc::new(std::sync::atomic::AtomicBool::new(false)),
            scope_filter: Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    pub fn set_enabled(&self, v: bool) {
        self.enabled.store(v, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Set scope filter — only these hosts will be intercepted (empty = all)
    pub fn set_scope_filter(&self, hosts: Vec<String>) {
        if let Ok(mut f) = self.scope_filter.write() {
            *f = hosts;
        }
    }

    /// Check if host is in intercept scope
    pub fn in_scope(&self, host: &str) -> bool {
        if let Ok(f) = self.scope_filter.read() {
            if f.is_empty() { return true; }
            return f.iter().any(|h| h == host || host.ends_with(&format!(".{}", h)));
        }
        true
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Hold a flow — blocks until forward/drop called
    /// Returns the action to take
    pub async fn hold(&self, flow_id: &str) -> InterceptAction {
        let (tx, rx) = oneshot::channel();
        self.pending.insert(flow_id.to_string(), tx);

        // Wait for UI decision (max 120s then auto-forward)
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(120),
            rx,
        ).await {
            Ok(Ok(action)) => action,
            _ => {
                self.pending.remove(flow_id);
                InterceptAction::Forward
            }
        }
    }

    /// Forward a held flow (optionally with modifications)
    pub fn forward(&self, flow_id: &str) {
        if let Some((_, tx)) = self.pending.remove(flow_id) {
            let _ = tx.send(InterceptAction::Forward);
        }
    }

    pub fn forward_modified(
        &self,
        flow_id: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) {
        if let Some((_, tx)) = self.pending.remove(flow_id) {
            let _ = tx.send(InterceptAction::ForwardModified { headers, body });
        }
    }

    pub fn drop_flow(&self, flow_id: &str) {
        if let Some((_, tx)) = self.pending.remove(flow_id) {
            let _ = tx.send(InterceptAction::Drop);
        }
    }

    pub fn forward_all(&self) {
        let ids: Vec<String> = self.pending.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            self.forward(&id);
        }
    }

    pub fn get_pending_ids(&self) -> Vec<String> {
        self.pending.iter().map(|e| e.key().clone()).collect()
    }
}
