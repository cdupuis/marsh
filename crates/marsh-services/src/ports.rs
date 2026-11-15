//! Published-port tracking from the production engine's event stream.
//!
//! The watcher keeps, per workspace scope (the `dev.marsh.scope` label), the
//! set of TCP ports published by running containers, and reports the whole
//! state to the host as a `ports` frame whenever it changes. It reacts to
//! engine events (start, die, stop, ...), coalescing bursts, and re-lists
//! after every reconnect, so it never depends on a poll interval.

use crate::engine_api::{ContainerSummary, Engine, SCOPE_LABEL};
use crate::frame::{AgentFrame, ScopePorts};
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::time::Duration;

const MAX_SCOPES: usize = 256;
const MAX_PORTS_PER_SCOPE: usize = 512;
const ACTIONS: &[&str] = &[
    "start", "die", "stop", "kill", "destroy", "restart", "oom", "create", "rename",
];

fn snapshot(
    engine: &Engine,
    admitted: &dyn Fn(&str, &str) -> bool,
) -> Option<BTreeMap<String, BTreeSet<u16>>> {
    let containers = engine.list_containers(false).ok()?;
    Some(scope_ports(&containers, admitted))
}

/// The ports each scope publishes on the address the relay dials. A binding
/// on another address is not the relay's to reach, so it never counts: the
/// same port on `127.0.0.2` in one scope and `127.0.0.1` in another is not
/// one port listed for two workspaces.
fn scope_ports(
    containers: &[ContainerSummary],
    admitted: &dyn Fn(&str, &str) -> bool,
) -> BTreeMap<String, BTreeSet<u16>> {
    let mut map: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    for container in containers.iter().filter(|c| c.state == "running") {
        let Some(scope) = container.label(SCOPE_LABEL) else {
            continue;
        };
        // Only what the policy admitted into this scope: a label alone is not authority.
        if !admitted(scope, &container.id) {
            continue;
        }
        for port in container.ports.iter().flatten() {
            if port.is_relay_tcp() {
                map.entry(scope.to_owned())
                    .or_default()
                    .insert(port.public_port);
            }
        }
    }
    map
}

fn frame_for(map: &BTreeMap<String, BTreeSet<u16>>) -> AgentFrame {
    let mut truncated = map.len() > MAX_SCOPES;
    let scopes = map
        .iter()
        .take(MAX_SCOPES)
        .map(|(workspace, ports)| {
            truncated |= ports.len() > MAX_PORTS_PER_SCOPE;
            ScopePorts {
                workspace: workspace.clone(),
                ports: ports.iter().copied().take(MAX_PORTS_PER_SCOPE).collect(),
            }
        })
        .collect();
    AgentFrame::Ports { scopes, truncated }
}

/// Starts the watcher thread. `send` delivers frames to the host.
///
/// `admitted(scope, container id)` says whether the policy admitted that
/// container into the scope; the label alone is never enough.
pub fn spawn_watcher(
    engine: Engine,
    admitted: impl Fn(&str, &str) -> bool + Send + 'static,
    send: impl Fn(AgentFrame) + Send + 'static,
) {
    std::thread::spawn(move || {
        let mut first = true;
        let mut current: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
        loop {
            if let Ok(mut reader) = engine.events() {
                let _ = reader
                    .get_ref()
                    .set_read_timeout(Some(Duration::from_millis(40)));
                let mut dirty = true;
                let mut quiet = true;
                let mut line = String::new();
                loop {
                    if dirty && quiet {
                        dirty = false;
                        if let Some(now) = snapshot(&engine, &admitted) {
                            let changed = current != now;
                            if changed {
                                current.clone_from(&now);
                            }
                            if changed || first {
                                first = false;
                                send(frame_for(&now));
                            }
                        }
                    }
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            quiet = false;
                            if line.ends_with('\n') {
                                if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line)
                                {
                                    let action = event["Action"].as_str().unwrap_or_default();
                                    dirty |= ACTIONS.contains(&action);
                                }
                                line.clear();
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            quiet = true;
                        }
                        Err(_) => break,
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_api::ContainerSummary;

    fn running(id: &str, scope: &str, ports: &str) -> ContainerSummary {
        serde_json::from_str(&format!(
            r#"{{"Id":"{id}","State":"running","Labels":{{"dev.marsh.scope":"{scope}"}},"Ports":{ports}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn two_scopes_on_one_port_at_different_loopback_addresses_do_not_collide() {
        // The base publishes 127.0.0.1:8080; a lane publishes 127.0.0.2:8080 and
        // [::1]:8080. Both are valid for dockerd, and the relay dials only
        // 127.0.0.1, so only the base owns the port: no scope pair shares one.
        let containers = [
            running(
                "a",
                "base",
                r#"[{"IP":"127.0.0.1","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]"#,
            ),
            running(
                "b",
                "lane",
                r#"[{"IP":"127.0.0.2","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},{"IP":"::1","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]"#,
            ),
        ];
        let map = scope_ports(&containers, &|_, _| true);
        assert_eq!(map.get("base"), Some(&BTreeSet::from([8080])));
        assert_eq!(map.get("lane"), None);
        let seen: usize = map.values().map(BTreeSet::len).sum();
        assert_eq!(seen, 1, "{map:?}");
    }
}
