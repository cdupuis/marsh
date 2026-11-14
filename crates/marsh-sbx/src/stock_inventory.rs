//! Validated public `sbx ls --json` inventory decoder.
use crate::{SbxError, safe_absolute};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const MAX_VMS: usize = 4096;
const MAX_DOCUMENT: usize = 4 * 1024 * 1024;

fn invalid(message: &str) -> SbxError {
    SbxError::HostGrantFence(message.into())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct StockInventoryVm {
    pub name: String,
    pub id: String,
    pub status: String,
    pub agent: Option<String>,
    pub workspaces: Option<Vec<PathBuf>>,
    /// When stock SBX last ran something in it (RFC 3339), if it says.
    #[serde(default)]
    pub last_used_at: Option<String>,
}

impl StockInventoryVm {
    /// Whether the VM may be running: anything but `stopped`. A state marsh
    /// does not know (a VM being created or started) is never taken for
    /// stopped, so nothing removes or skips it as idle.
    #[must_use]
    pub fn possibly_running(&self) -> bool {
        self.status != "stopped"
    }
}

/// Validated complete inventory data, not source-observation authority. No
/// Deserialize implementation or public constructor bypasses the decoder.
#[derive(Debug, Eq, PartialEq)]
pub struct StockInventory {
    vms: BTreeMap<String, StockInventoryVm>,
}

impl StockInventory {
    /// Decode one complete public `sbx ls --json` document.
    ///
    /// # Errors
    /// Rejects unknown shapes, duplicate name/UUID, unsafe names, unsupported
    /// states, malformed paths/UUIDs and oversized/incomplete inventories.
    pub fn decode(bytes: &[u8]) -> Result<Self, SbxError> {
        if bytes.len() > MAX_DOCUMENT {
            return Err(invalid("stock inventory exceeds its byte bound"));
        }
        let document: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid stock inventory JSON"))?;
        // Stock SBX has emitted both `{"sandboxes": [...]}` and a bare `[...]`;
        // any other envelope is unknown.
        let rows = match &document {
            serde_json::Value::Array(_) => &document,
            serde_json::Value::Object(object)
                if object.len() == 1 && object.contains_key("sandboxes") =>
            {
                &object["sandboxes"]
            }
            _ => return Err(invalid("unknown or incomplete stock inventory envelope")),
        };
        let rows = rows
            .as_array()
            .filter(|rows| rows.len() <= MAX_VMS)
            .ok_or_else(|| invalid("stock inventory has missing or excessive rows"))?;
        let mut vms = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for row in rows {
            let Some(object) = row.as_object() else {
                return Err(invalid("unknown stock inventory row schema"));
            };
            // Extra keys are ignored: stock adds fields to some rows (a VM
            // with published ports, a cloud or detached one) and marsh reads
            // only the five below. Every row must establish an identity, a
            // name and a valid UUID: a row that cannot is never skipped,
            // because the VM it describes may be one of ours and a "complete"
            // inventory without it would call that VM absent. A row of
            // another tool (a name not starting `marsh-`) is kept for its
            // identity, but its state and paths are not marsh's to judge.
            let name = object.get("name").and_then(serde_json::Value::as_str);
            let id = object.get("id").and_then(serde_json::Value::as_str);
            let (Some(name), Some(id)) = (name, id) else {
                return Err(invalid("stock inventory row without a name and id"));
            };
            let ours = name.starts_with("marsh-");
            let text = |key: &str| object.get(key).and_then(serde_json::Value::as_str);
            let status = text("status").filter(|status| {
                !status.is_empty() && status.len() <= 64 && !status.chars().any(char::is_control)
            });
            // Any state name is kept: a VM of ours still being created or
            // started has one marsh does not know, and rejecting it would fail
            // every operation for every VM. A row of ours must still have a
            // status; another tool's may lack one.
            let status = match (status, ours) {
                (Some(status), _) => status,
                (None, false) => "unknown",
                (None, true) => return Err(invalid("incomplete stock inventory row")),
            };
            let mut vm = StockInventoryVm {
                name: name.to_owned(),
                id: id.to_owned(),
                status: status.to_owned(),
                agent: text("agent").filter(|_| ours).map(str::to_owned),
                // Paths are informational: a malformed list is no list.
                workspaces: object
                    .get("workspaces")
                    .filter(|_| ours)
                    .and_then(serde_json::Value::as_array)
                    .and_then(|paths| {
                        paths
                            .iter()
                            .map(|path| path.as_str().map(PathBuf::from))
                            .collect::<Option<Vec<_>>>()
                    })
                    .filter(|paths| paths.iter().all(|path| metadata_path(path))),
                last_used_at: text("last_used_at").filter(|_| ours).map(str::to_owned),
            };
            vm.id.make_ascii_lowercase();
            let sound = valid_uuid(&vm.id)
                && !vm.name.is_empty()
                && vm.name.len() <= 256
                && (!ours || valid_name(&vm.name));
            if !sound || !ids.insert(vm.id.clone()) || vms.contains_key(&vm.name) {
                return Err(invalid(
                    "ambiguous, changing or unsupported stock inventory identity/state",
                ));
            }
            vms.insert(vm.name.clone(), vm);
        }
        Ok(Self { vms })
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&StockInventoryVm> {
        self.vms.get(name)
    }

    /// Every listed VM name.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.vms.keys().map(String::as_str)
    }

    #[must_use]
    pub fn proves_names_absent(&self, names: &BTreeSet<String>) -> bool {
        names.iter().all(|name| !self.vms.contains_key(name))
    }

    #[must_use]
    pub fn contains_uuid(&self, uuid: &str) -> bool {
        self.vms.values().any(|vm| vm.id.eq_ignore_ascii_case(uuid))
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
        && id
            .bytes()
            .any(|byte| matches!(byte, b'1'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
}

fn metadata_path(path: &Path) -> bool {
    // Go JSON replaces invalid Unix UTF8. A replacement spelling cannot prove
    // identity when raw and Unicode-replacement filenames coexist on the host.
    path.as_os_str().len() <= 4096
        && path.components().count() <= 128
        && (safe_absolute(path) || path == Path::new("/"))
        && path.to_str().is_some_and(|path| !path.contains('\u{fffd}'))
}

#[cfg(test)]
mod tests {
    //! Rejections; every captured or derived listing decoding is covered by
    //! `tests::stock_cli` against `tests/data/sbx`.
    use super::StockInventory;

    const V047: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/sbx/v0.47.0/ls-json.stdout"
    ));
    const V047_DEV: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/sbx/v0.47-dev/ls-json.stdout"
    ));

    const V050: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/sbx/v0.50.0/ls-json.stdout"
    ));

    /// The first row of a real listing with one key added.
    fn with_key(listing: &[u8], key: &str, value: serde_json::Value) -> Vec<u8> {
        let mut document: serde_json::Value = serde_json::from_slice(listing).unwrap();
        let rows = match document.get_mut("sandboxes") {
            Some(rows) => rows,
            None => &mut document,
        };
        rows[0][key] = value;
        serde_json::to_vec(&document).unwrap()
    }

    #[test]
    fn real_listings_decode_and_a_row_with_an_extra_key_still_does() {
        // v0.50.0: a trimmed real `sbx ls --json` (a running and a stopped
        // marsh VM, another tool's sandbox, one whose workspace is missing).
        for listing in [V047, V047_DEV, V050] {
            assert!(StockInventory::decode(listing).is_ok());
            for (key, value) in [
                (
                    "ports",
                    serde_json::json!([{"host_port": 8080, "sandbox_port": 80}]),
                ),
                ("surprise", serde_json::json!({"nested": true})),
            ] {
                let decoded = StockInventory::decode(&with_key(listing, key, value)).unwrap();
                assert!(decoded.get("marsh-k-aaaaaaaa").is_some() || listing != V050);
            }
        }
    }

    #[test]
    fn another_tools_row_is_kept_for_its_identity_and_a_row_without_one_fails_closed() {
        let ours = r#"{"name":"marsh-k-aaaaaaaa","id":"0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9","status":"running"}"#;
        let theirs_odd = r#"{"name":"other","id":"1f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9","status":"paused","workspaces":["relative"]}"#;
        let theirs_no_status = r#"{"name":"quiet","id":"2f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9"}"#;
        let decoded =
            StockInventory::decode(format!("[{ours},{theirs_odd},{theirs_no_status}]").as_bytes())
                .unwrap();
        assert!(decoded.get("marsh-k-aaaaaaaa").is_some());
        assert!(
            decoded
                .get("other")
                .is_some_and(|vm| vm.workspaces.is_none())
        );
        assert!(decoded.get("quiet").is_some());
        // An owned UUID under a missing or non-string name, or no id at all,
        // is an error, never an absent VM.
        for broken in [
            r#"{"id":"0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9","status":"running"}"#,
            r#"{"name":7,"id":"0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9","status":"running"}"#,
            r#"{"name":"broken","status":"running"}"#,
            r#"{"name":"broken","id":"not-a-uuid","status":"running"}"#,
        ] {
            assert!(StockInventory::decode(format!("[{broken}]").as_bytes()).is_err());
        }
        for ours_bad in [
            ours.replace("\"status\":\"running\"", "\"status\":7"),
            ours.replace("\"name\":\"marsh-k-aaaaaaaa\"", "\"name\":\"marsh-k-a/b\""),
        ] {
            assert!(StockInventory::decode(format!("[{ours_bad}]").as_bytes()).is_err());
        }
    }

    /// Audit B-05: one of marsh's own VMs in a state or shape marsh does not
    /// know (a VM still being created, a workspace path that is not absolute)
    /// must not fail the whole listing, and with it every operation. Its
    /// identity is sound, so the VM stays listed under its name.
    #[test]
    fn a_marsh_vm_in_a_transient_state_or_with_an_odd_workspace_keeps_the_listing() {
        let ours = r#"{"name":"marsh-k-aaaaaaaa","id":"0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9","status":"running"}"#;
        for odd in [
            ours.replace("running", "creating"),
            ours.replace("running", "starting"),
            ours.replace("running\"", "running\",\"workspaces\":[\"relative\"]"),
            ours.replace("running\"", "running\",\"workspaces\":\"/not/a/list\""),
        ] {
            let decoded = StockInventory::decode(format!("[{odd}]").as_bytes()).unwrap();
            let vm = decoded.get("marsh-k-aaaaaaaa").unwrap();
            assert_eq!(vm.id, "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9");
            assert!(vm.workspaces.is_none());
        }
    }

    #[test]
    fn only_stopped_is_not_possibly_running() {
        let row = |status: &str| {
            let listing = format!(
                r#"[{{"name":"marsh-k-aaaaaaaa","id":"0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9","status":"{status}"}}]"#
            );
            StockInventory::decode(listing.as_bytes()).unwrap()
        };
        for (status, running) in [
            ("running", true),
            ("stopped", false),
            ("starting", true),
            ("creating", true),
            ("stopping", true),
        ] {
            assert_eq!(
                row(status)
                    .get("marsh-k-aaaaaaaa")
                    .unwrap()
                    .possibly_running(),
                running,
                "{status}"
            );
        }
    }

    #[test]
    fn a_long_listing_is_decoded_and_an_absurd_one_is_not() {
        let rows = |count: usize| {
            (0..count)
                .map(|index| {
                    format!(
                        r#"{{"name":"other-{index}","id":"{index:08x}-4b5a-4978-8695-a4b3c2d1e0f9","status":"running"}}"#
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        let decoded = StockInventory::decode(format!("[{}]", rows(300)).as_bytes()).unwrap();
        assert!(decoded.get("other-299").is_some());
        assert!(StockInventory::decode(format!("[{}]", rows(5000)).as_bytes()).is_err());
    }

    #[test]
    fn unknown_envelopes_are_rejected_and_an_empty_listing_is_not() {
        assert!(StockInventory::decode(b"[]").is_ok());
        assert!(StockInventory::decode(br#"{"sandboxes":[]}"#).is_ok());
        for envelope in [
            &br#"{"sandboxes":[],"next":null}"#[..],
            br#"{"vms":[]}"#,
            br#""sandboxes""#,
        ] {
            assert!(StockInventory::decode(envelope).is_err());
        }
    }

    #[test]
    fn duplicate_identities_are_rejected() {
        let row = r#"{"name":"a","id":"0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9","status":"running"}"#;
        let renamed = row.replace("\"a\"", "\"b\"");
        assert!(StockInventory::decode(format!("[{row},{renamed}]").as_bytes()).is_err());
        let rekeyed = row.replace("0f1e2d3c", "1f1e2d3c");
        assert!(StockInventory::decode(format!("[{row},{rekeyed}]").as_bytes()).is_err());
    }
}
