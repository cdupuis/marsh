//! Session-owned ephemeral Kit selectors. Authority is the existing native
//! private-slot token/ledger, not this in-memory cleanup map.
use super::*;

/// The ownership key of a session's ephemeral Kit VM.
fn ephemeral_ownership_key(identity: &str, session: &str) -> String {
    format!("{identity}:ephemeral:{session}")
}

/// Every lock of `locks`, in order, polling each until `deadline`; refused
/// (an ephemeral Kit preparation has not drained) when one stays held.
fn lock_all_before(
    locks: &[Arc<Mutex<()>>],
    deadline: Instant,
) -> Result<Vec<std::sync::MutexGuard<'_, ()>>, DaemonError> {
    let mut guards = Vec::new();
    for lock in locks {
        loop {
            match lock.try_lock() {
                Ok(guard) => {
                    guards.push(guard);
                    break;
                }
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    guards.push(error.into_inner());
                    break;
                }
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => {
                    return Err(DaemonError::ShellCleanupUncertain(
                        "ephemeral Kit preparation has not drained; private slot retained".into(),
                    ));
                }
            }
        }
    }
    Ok(guards)
}

impl StockDaemonBackend {
    pub(super) fn kit_spec_for_session(
        &self,
        command: &str,
        session: &SessionSpec,
        store: &DaemonStore,
    ) -> Result<KitVmSpec, DaemonError> {
        let mut spec = self.kit_spec(command)?;
        if !session.ephemeral_home {
            return Ok(spec);
        }
        let token = store
            .ephemeral_home_token(&session.session_id)
            .ok_or_else(|| {
                DaemonError::InvalidState(
                    "ephemeral Kit requires the immutable host allocation binding".into(),
                )
            })?;
        self.sbx
            .ephemeral_home_grant(&token, &session.home_backing, &session.guest_home)
            .map_err(backend_error)?;
        spec.name = self
            .sbx
            .vm_name(
                VmPurpose::Kit,
                &ephemeral_ownership_key(spec.workload_kit.identity(), &session.session_id),
            )
            .map_err(backend_error)?;
        // Reusing the private leaf also for the implicit Kit Create workspace
        // avoids a new ordinary kit-lifecycle history row for every session.
        spec.lifecycle_workspace.clone_from(&session.home_backing);
        self.ephemeral_kits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(session.session_id.clone())
            .or_default()
            .insert(spec.name.clone(), spec.clone());
        Ok(spec)
    }

    pub(super) fn close_ephemeral_kits(
        &self,
        session: &str,
        store: &DaemonStore,
    ) -> Result<(), DaemonError> {
        if store.ephemeral_home_token(session).is_none() {
            return Ok(());
        }
        let specs = self
            .ephemeral_kits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(session)
            .cloned()
            .unwrap_or_default();
        // One Kit lock per ownership key of the session (as its preparations
        // take them: `kit_lock_key`), in key order.
        let owners = specs
            .values()
            .map(|spec| ephemeral_ownership_key(spec.workload_kit.identity(), session))
            .collect::<BTreeSet<_>>();
        let keys = owners
            .iter()
            .map(|owner| self.kit_lock_key(owner))
            .collect::<Result<Vec<_>, DaemonError>>()?;
        let locks = self.kit_locks_in_order(&owners)?;
        let deadline = Instant::now() + Duration::from_secs(90);
        let _guards = lock_all_before(&locks, deadline)?;
        // Under those locks: every VM the session's keys own, not only the
        // names noted before a preparation chose (`KitInstall.tla`
        // `ephStaleName`): a preparation may recover the noted VM and create
        // under a new name.
        let mut specs = specs;
        for (name, owner) in self.sbx.live_kit_entries() {
            if !owners.contains(&owner) || specs.contains_key(&name) {
                continue;
            }
            if let Some(template) = specs.values().find(|spec| {
                ephemeral_ownership_key(spec.workload_kit.identity(), session) == owner
            }) {
                let mut spec = template.clone();
                spec.name.clone_from(&name);
                specs.insert(name, spec);
            }
        }
        let names = specs.keys().cloned().collect::<Vec<_>>();
        store.begin_workers_reset(&names).map_err(|error| {
            DaemonError::ShellCleanupUncertain(format!(
                "ephemeral Kit still active; HOME retained: {error}"
            ))
        })?;
        for (index, (name, spec)) in specs.iter().enumerate() {
            if let Err(error) = self.sbx.reset_kit_vm_before(spec, deadline) {
                let _ = store.finish_worker_reset(name, false);
                store.cancel_workers_reset(&names[index + 1..]);
                return Err(DaemonError::ShellCleanupUncertain(format!(
                    "ephemeral Kit {name} exact UUID removal not verified: {error}"
                )));
            }
            store.finish_worker_reset(name, true)?;
            self.ready_kits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|_, ready| ready.name != *name);
            self.registered_workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(name);
        }
        // Closing the native token fenced all late private begins before these
        // locks were acquired. Removing cache selectors never releases authority.
        self.ephemeral_kits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session);
        let mut flights = self
            .kit_validation_flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in &keys {
            flights.remove(key);
        }
        let mut all_locks = self
            .kit_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in &keys {
            all_locks.remove(key);
        }
        store.finish_ephemeral_session(session);
        Ok(())
    }

    /// The ownership keys of the live ephemeral-home sessions' Kit VMs.
    pub(super) fn live_ephemeral_keys(&self) -> BTreeSet<String> {
        self.ephemeral_kits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .flat_map(|(session, specs)| {
                specs
                    .values()
                    .map(|spec| ephemeral_ownership_key(spec.workload_kit.identity(), session))
            })
            .collect()
    }

    pub(super) fn remembered_ephemeral_kits(&self) -> Vec<KitVmSpec> {
        self.ephemeral_kits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .flat_map(|specs| specs.values().cloned())
            .collect()
    }
}
