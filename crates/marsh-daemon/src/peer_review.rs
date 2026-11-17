//! Peer review by another vendor's model (`docs/peer-review.md`).
//!
//! marsh owns the model classes: a curated table (`data/model-classes.yaml`,
//! overridable in `$MARSH_HOME/model-classes.yaml`) of current families and a
//! list of retired ones. Only curated models are ever picked or advertised
//! automatically. For display, a model no rule names is still classed by its
//! output price in a models.dev snapshot taken in CI (`data/models-dev.json`,
//! `scripts/update-models-dev.py`), but it is not eligible; nothing is
//! fetched at run time. Who may review comes from `$MARSH_HOME/peer-review.d/
//! *.yaml` drop-ins (Narwhal writes `narwhal.yaml`, `marsh config peer-review
//! on` writes `marsh.yaml`), read whenever they are needed (every job start
//! and `marsh status`), so an edit applies to the next job.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub use marsh_contracts::process::ModelChoice;

/// The drop-in directory under `$MARSH_HOME`.
pub const DROPIN_DIR: &str = "peer-review.d";
/// The drop-in `marsh config peer-review on|off` writes.
pub const MARSH_DROPIN: &str = "marsh.yaml";
/// The class table override under `$MARSH_HOME`.
pub const OVERRIDE_FILE: &str = "model-classes.yaml";
const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_REVIEWERS: usize = 64;
const MAX_NAME_BYTES: usize = 128;
/// Rows of the reviewer table in `context.md`.
const CONTEXT_ROWS: usize = 8;
/// Models listed per agent in the `task` tool's description.
const CHOICE_ROWS: usize = 8;
/// A family whose newest model is older than the vendor's newest listed
/// model by more than this many days is left out of the list.
const CHOICE_RECENT_DAYS: i64 = 180;

const BUILTIN_TABLE: &str = include_str!("../data/model-classes.yaml");
const SNAPSHOT: &str = include_str!("../data/models-dev.json");
const ALIASES: &str = include_str!("../data/vendor-aliases.json");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelClass {
    Small,
    Mid,
    Large,
}

impl ModelClass {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Mid => "mid",
            Self::Large => "large",
        }
    }

    pub const ALL: [Self; 3] = [Self::Small, Self::Mid, Self::Large];
}

/// Output-price bands (USD per million output tokens) for models no rule
/// names: below `small_below` is small, from `large_from` up is large.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bands {
    pub small_below: f64,
    pub large_from: f64,
}

impl Bands {
    #[must_use]
    pub fn class(&self, output: f64) -> ModelClass {
        if output < self.small_below {
            ModelClass::Small
        } else if output >= self.large_from {
            ModelClass::Large
        } else {
            ModelClass::Mid
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(rename = "match")]
    pattern: String,
    class: ModelClass,
    vendor: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableFile {
    #[serde(default)]
    bands: Option<Bands>,
    #[serde(default)]
    rules: Vec<Rule>,
    /// Globs of superseded models: never eligible, whatever else matches
    /// them later in the table.
    #[serde(default)]
    retired: Vec<String>,
}

/// What a table entry says about the models it matches.
#[derive(Clone, Debug)]
enum Kind {
    Rule(Rule),
    Retired(String),
}

#[derive(Clone, Debug)]
struct Entry {
    kind: Kind,
    origin: &'static str,
}

impl Entry {
    fn pattern(&self) -> &str {
        match &self.kind {
            Kind::Rule(rule) => &rule.pattern,
            Kind::Retired(pattern) => pattern,
        }
    }
}

/// How a model was classed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Classified {
    /// `None` for a retired model the table and snapshot give no class.
    pub class: Option<ModelClass>,
    /// The model's maker; `None` when models.dev names none that marsh can
    /// trust (the host that lists a model is never its vendor), so it can
    /// only be paired with an explicit `vendor`.
    pub vendor: Option<String>,
    /// `model-classes: claude-sonnet-*`, `$MARSH_HOME/model-classes.yaml:
    /// my-*`, `models.dev family gpt-sol: gpt-*sol*`, `models.dev price
    /// $5/M output` (not curated), or `retired`.
    pub how: String,
    /// Curated and not retired: the only models marsh picks or lists by
    /// itself. A price-band class is for display only.
    pub eligible: bool,
}

/// `Classified::how` of a retired model.
pub const RETIRED: &str = "retired";

/// The effective class table, in order: the override's retired globs and
/// rules, then marsh's retired globs and rules. The first entry that matches
/// a model decides, so an override rule revives a model marsh retired.
#[derive(Clone, Debug)]
pub struct ClassTable {
    entries: Vec<Entry>,
    bands: Bands,
    /// The compiled-in snapshot; a test builds a table over another one.
    snapshot: &'static Snapshot,
}

const BUILTIN: &str = "model-classes";
const OVERRIDE: &str = "$MARSH_HOME/model-classes.yaml";

impl ClassTable {
    /// marsh's curated table alone.
    ///
    /// # Panics
    /// When the shipped table is malformed (a unit test keeps it parsing).
    #[must_use]
    pub fn builtin() -> Self {
        let file: TableFile =
            serde_yaml::from_str(BUILTIN_TABLE).expect("data/model-classes.yaml parses");
        Self {
            entries: entries(file.retired, file.rules, BUILTIN),
            bands: file.bands.expect("data/model-classes.yaml has bands"),
            snapshot: snapshot(),
        }
    }

    /// marsh's curated table over `snapshot` instead of the compiled-in one
    /// (the seam that lets a test add a model the snapshot lacks).
    #[cfg(test)]
    fn with_snapshot(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Box::leak(Box::new(snapshot)),
            ..Self::builtin()
        }
    }

    /// marsh's table with `$MARSH_HOME/model-classes.yaml` over it. A
    /// malformed override is ignored and its error returned.
    #[must_use]
    pub fn load(scope: &Path) -> (Self, Option<String>) {
        let mut table = Self::builtin();
        let path = scope.join(OVERRIDE_FILE);
        match read_small(&path) {
            Ok(None) => (table, None),
            Ok(Some(text)) => match parse_table(&text) {
                Ok(file) => {
                    if let Some(bands) = file.bands {
                        table.bands = bands;
                    }
                    let mut found = entries(file.retired, file.rules, OVERRIDE);
                    found.append(&mut table.entries);
                    table.entries = found;
                    (table, None)
                }
                Err(error) => (table, Some(format!("{}: {error}", path.display()))),
            },
            Err(error) => (table, Some(error)),
        }
    }

    #[must_use]
    pub const fn bands(&self) -> Bands {
        self.bands
    }

    fn entry_for(&self, text: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| glob(&entry.pattern().to_ascii_lowercase(), text))
    }

    fn rule_for(&self, text: &str) -> Option<(&Rule, &'static str)> {
        self.entries.iter().find_map(|entry| match &entry.kind {
            Kind::Rule(rule) if glob(&rule.pattern.to_ascii_lowercase(), text) => {
                Some((rule, entry.origin))
            }
            _ => None,
        })
    }

    /// The rule that makes a model curated: the first entry matching its
    /// name, else its models.dev family, when that entry is a rule and not
    /// a retirement.
    fn curated(&self, name: &str, family: &str) -> Option<(&Rule, &'static str)> {
        let entry = self.entry_for(name).or_else(|| {
            (!family.is_empty())
                .then(|| self.entry_for(family))
                .flatten()
        })?;
        match &entry.kind {
            Kind::Rule(rule) => Some((rule, entry.origin)),
            Kind::Retired(_) => None,
        }
    }

    /// The class and vendor of `model` (an id as the agent's model option
    /// takes it, optionally `provider/model`): the first entry matching its
    /// name or its models.dev family, else, for display only, its models.dev
    /// output price. Only a model a rule names is `eligible`; a retired one
    /// is not, and says `retired`.
    #[must_use]
    pub fn classify(&self, model: &str) -> Option<Classified> {
        let name = normalize(model);
        if name.is_empty() {
            return None;
        }
        let row = self.snapshot.lookup(model);
        let family = row.map_or_else(String::new, |row| row.family.to_ascii_lowercase());
        let by_name = self.entry_for(&name);
        let by_family = (by_name.is_none() && !family.is_empty())
            .then(|| self.entry_for(&family))
            .flatten();
        match (by_name, by_family) {
            (
                Some(Entry {
                    kind: Kind::Rule(rule),
                    origin,
                }),
                _,
            ) => {
                return Some(Classified {
                    class: Some(rule.class),
                    vendor: Some(rule.vendor.clone()),
                    how: format!("{origin}: {}", rule.pattern),
                    eligible: true,
                });
            }
            (
                _,
                Some(Entry {
                    kind: Kind::Rule(rule),
                    origin,
                }),
            ) => {
                return Some(Classified {
                    class: Some(rule.class),
                    vendor: Some(rule.vendor.clone()),
                    how: format!("models.dev family {family}; {origin}: {}", rule.pattern),
                    eligible: true,
                });
            }
            (None, None) => {}
            // Retired: the class and vendor are for display.
            _ => {
                let shown = self.rule_for(&name).or_else(|| {
                    (!family.is_empty())
                        .then(|| self.rule_for(&family))
                        .flatten()
                });
                return Some(Classified {
                    class: shown
                        .map(|(rule, _)| rule.class)
                        .or_else(|| row.map(|row| self.bands.class(row.output))),
                    vendor: shown.map(|(rule, _)| rule.vendor.clone()).or_else(|| {
                        row.and_then(|row| (!row.vendor.is_empty()).then(|| row.vendor.clone()))
                    }),
                    how: RETIRED.into(),
                    eligible: false,
                });
            }
        }
        let row = row?;
        Some(Classified {
            class: Some(self.bands.class(row.output)),
            vendor: (!row.vendor.is_empty()).then(|| row.vendor.clone()),
            how: format!("models.dev price ${}/M output", row.output),
            eligible: false,
        })
    }

    /// The newest model of `vendor` in `class` that the vendor itself serves,
    /// by the rules alone (what `marsh config peer-review on` offers).
    #[must_use]
    pub fn newest(&self, vendor: &str, class: ModelClass) -> Option<String> {
        let mut best: Option<&SnapshotModel> = None;
        for row in
            self.snapshot.models.iter().filter(|row| {
                row.vendor == vendor && row.first_party() && plain_chat_model(&row.id)
            })
        {
            let name = normalize(&row.id);
            let family = row.family.to_ascii_lowercase();
            let Some((rule, _)) = self.curated(&name, &family) else {
                continue;
            };
            if rule.class != class || rule.vendor != vendor {
                continue;
            }
            let better = best.is_none_or(|best| {
                (row.released.as_str(), std::cmp::Reverse(row.id.len()))
                    > (best.released.as_str(), std::cmp::Reverse(best.id.len()))
            });
            if better {
                best = Some(row);
            }
        }
        best.map(|row| row.id.clone())
    }

    /// The models of `vendors` an agent can be asked for by name: each
    /// family's newest model the vendor itself serves (`luna`, `terra`,
    /// `sol`, `astra`; `haiku`, `sonnet`), without families a half year
    /// behind the vendor's newest, at most `CHOICE_ROWS` rows by recency,
    /// ordered by class. `qualify` writes `vendor/model`, the id a
    /// multi-provider agent takes.
    #[must_use]
    pub fn choices(&self, vendors: &[String], qualify: bool) -> Vec<ModelChoice> {
        let mut picked = Vec::<(String, &SnapshotModel, ModelClass, String)>::new();
        for vendor in vendors {
            let mut families = BTreeMap::<String, (&SnapshotModel, ModelClass)>::new();
            for row in self.snapshot.models.iter().filter(|row| {
                row.vendor == *vendor && row.first_party() && plain_chat_model(&row.id)
            }) {
                let name = normalize(&row.id);
                let family = row.family.to_ascii_lowercase();
                let Some((rule, _)) = self.curated(&name, &family) else {
                    continue;
                };
                if rule.vendor != *vendor {
                    continue;
                }
                let key = family_nickname(&rule.pattern);
                let better = families.get(&key).is_none_or(|(best, _)| {
                    (row.released.as_str(), std::cmp::Reverse(row.id.len()))
                        > (best.released.as_str(), std::cmp::Reverse(best.id.len()))
                });
                if better {
                    families.insert(key, (row, rule.class));
                }
            }
            let latest = families
                .values()
                .map(|(row, _)| day_number(&row.released))
                .max()
                .unwrap_or(0);
            for (key, (row, class)) in families {
                if day_number(&row.released) + CHOICE_RECENT_DAYS >= latest {
                    picked.push((vendor.clone(), row, class, key));
                }
            }
        }
        picked.sort_by(|a, b| b.1.released.cmp(&a.1.released).then(a.1.id.cmp(&b.1.id)));
        picked.truncate(CHOICE_ROWS);
        picked.sort_by(|a, b| {
            (a.2, &a.0, std::cmp::Reverse(&a.1.released)).cmp(&(
                b.2,
                &b.0,
                std::cmp::Reverse(&b.1.released),
            ))
        });
        picked
            .into_iter()
            .map(|(vendor, row, class, family)| ModelChoice {
                model: if qualify {
                    format!("{vendor}/{}", row.id)
                } else {
                    row.id.clone()
                },
                class: class.name().to_owned(),
                family,
            })
            .collect()
    }
}

fn entries(retired: Vec<String>, rules: Vec<Rule>, origin: &'static str) -> Vec<Entry> {
    retired
        .into_iter()
        .map(Kind::Retired)
        .chain(rules.into_iter().map(Kind::Rule))
        .map(|kind| Entry { kind, origin })
        .collect()
}

/// The nickname people use for the family a rule names: its last word that
/// is not a version (`gpt-*luna*` is `luna`, `claude-*-haiku*` is `haiku`).
fn family_nickname(pattern: &str) -> String {
    let pattern = pattern.to_ascii_lowercase();
    let words = pattern
        .split(['*', '-'])
        .filter(|word| !word.is_empty() && !word.starts_with(|c: char| c.is_ascii_digit()))
        .collect::<Vec<_>>();
    match words.as_slice() {
        // `mistral-large*` is `mistral-large`: a size alone names no family.
        [first, .., size @ ("small" | "medium" | "large")] => format!("{first}-{size}"),
        [.., last] => (*last).to_owned(),
        [] => pattern,
    }
}

/// Days since year 0 (365-day years, 31-day months: only for ordering and
/// distances of release dates `YYYY-MM-DD`); 0 for anything else.
fn day_number(date: &str) -> i64 {
    let mut parts = date.split('-').map(|part| part.parse::<i64>().ok());
    match (
        parts.next().flatten(),
        parts.next().flatten(),
        parts.next().flatten(),
    ) {
        (Some(year), Some(month), Some(day)) => year * 372 + month * 31 + day,
        _ => 0,
    }
}

/// The models an agent can run, from its Kit's credential services and, for
/// a multi-provider agent, the vendors its Kit reaches: what the `task`
/// tool lists for it (`ClassTable::choices`).
#[must_use]
pub fn agent_choices(
    table: &ClassTable,
    agent: &str,
    services: &[String],
    reaches: &BTreeMap<String, Vec<String>>,
) -> Vec<ModelChoice> {
    let any = services.iter().any(|service| service == ANY_PROVIDER);
    let reaches = reaches
        .iter()
        .map(|(service, hosts)| (service.clone(), hosts.iter().cloned().collect()))
        .collect::<BTreeMap<String, BTreeSet<String>>>();
    let vendors = if any {
        VENDOR_HOSTS
            .iter()
            .map(|(vendor, _)| (*vendor).to_owned())
            .filter(|vendor| cannot_reach(agent, vendor, &reaches).is_none())
            .collect::<Vec<_>>()
    } else {
        services
            .iter()
            .map(|service| vendor_name(service))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    table.choices(&vendors, any)
}

/// `nickname` (a family such as `astra`) as the model id `choices` gives it;
/// `None` when it names no family, or the id itself.
///
/// # Errors
/// Returns the candidates when several vendors have a family of that name.
pub fn resolve_family(
    choices: &[ModelChoice],
    nickname: &str,
) -> Result<Option<ModelChoice>, String> {
    let nickname = nickname.trim().to_ascii_lowercase();
    let found = choices
        .iter()
        .filter(|choice| choice.family == nickname)
        .collect::<Vec<_>>();
    match found.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some((*one).clone())),
        many => Err(format!(
            "`{nickname}` is more than one model here ({}): name one",
            many.iter()
                .map(|choice| choice.model.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The list of models in the `task` tool's description: `NAME: MODEL (CLASS,
/// FAMILY), ...` per agent with models.
#[must_use]
pub fn describe_choices(choices: &BTreeMap<String, Vec<ModelChoice>>) -> String {
    choices
        .iter()
        .filter(|(_, models)| !models.is_empty())
        .map(|(agent, models)| {
            let models = models
                .iter()
                .map(|choice| format!("{} ({}, {})", choice.model, choice.class, choice.family))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{agent}: {models}")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn parse_table(text: &str) -> Result<TableFile, String> {
    let file: TableFile = serde_yaml::from_str(text).map_err(|error| error.to_string())?;
    if let Some(bands) = file.bands
        && !(bands.small_below.is_finite()
            && bands.large_from.is_finite()
            && 0.0 <= bands.small_below
            && bands.small_below <= bands.large_from)
    {
        return Err("bands: need 0 <= small_below <= large_from".into());
    }
    for pattern in &file.retired {
        if pattern.trim().is_empty() || pattern.len() > MAX_NAME_BYTES {
            return Err(format!("retired {pattern:?}: a glob of 1-128 bytes"));
        }
    }
    for rule in &file.rules {
        if rule.pattern.trim().is_empty() || rule.pattern.len() > MAX_NAME_BYTES {
            return Err(format!("rule {:?}: `match` is 1-128 bytes", rule.pattern));
        }
        valid_vendor(&rule.vendor).map_err(|error| format!("rule {:?}: {error}", rule.pattern))?;
    }
    let mut file = file;
    for rule in &mut file.rules {
        rule.vendor = vendor_name(&rule.vendor);
    }
    Ok(file)
}

/// Ids that are not ordinary chat models, or are moving aliases.
fn plain_chat_model(id: &str) -> bool {
    const SKIP: [&str; 14] = [
        "latest",
        "preview",
        "-exp",
        "image",
        "tts",
        "live",
        "realtime",
        "audio",
        "search",
        "research",
        "codex",
        "computer-use",
        "customtools",
        "translate",
    ];
    let id = id.to_ascii_lowercase();
    !SKIP.iter().any(|word| id.contains(word))
        // Dated snapshots (`...-20250929`) repeat their undated name.
        && !id
            .rsplit('-')
            .next()
            .is_some_and(|tail| tail.len() == 8 && tail.bytes().all(|byte| byte.is_ascii_digit()))
}

/// A model id as the rules see it: lowercase, without `provider/`, a cloud
/// region or vendor prefix (`us.`, `global.anthropic.`), or a host suffix
/// (`@eu`, `:free`).
fn normalize(model: &str) -> String {
    const PREFIXES: [&str; 16] = [
        "global.",
        "us.",
        "eu.",
        "apac.",
        "jp.",
        "au.",
        "anthropic.",
        "openai.",
        "google.",
        "meta.",
        "mistral.",
        "deepseek.",
        "qwen.",
        "moonshotai.",
        "zai.",
        "minimax.",
    ];
    let model = model.trim().to_ascii_lowercase();
    let mut name = model.rsplit('/').next().unwrap_or_default();
    name = name.split(['@', ':']).next().unwrap_or_default();
    while let Some(rest) = PREFIXES.iter().find_map(|prefix| name.strip_prefix(prefix)) {
        name = rest;
    }
    name.to_owned()
}

/// A model's name across hosts (`grok-4.6` on one, `grok-4-6` on another),
/// as the snapshot generator groups them.
fn name_key(model: &str) -> String {
    normalize(model).replace('.', "-")
}

/// `*` matches any run of characters; everything else matches itself.
fn glob(pattern: &str, text: &str) -> bool {
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

#[derive(Debug, Deserialize)]
struct SnapshotModel {
    provider: String,
    id: String,
    family: String,
    /// The model's maker, canonical (`vendor_name`); "" when unknown.
    vendor: String,
    output: f64,
    #[allow(dead_code)]
    open_weights: bool,
    released: String,
}

impl SnapshotModel {
    /// The vendor's own listing of its model.
    fn first_party(&self) -> bool {
        !self.vendor.is_empty() && vendor_name(&self.provider) == self.vendor
    }
}

/// A maker's canonical vendor id: lowercase, a leading `~` dropped, and
/// spellings such as `x-ai` or `zhipuai` mapped by `data/vendor-aliases.json`
/// (which the snapshot generator applies too).
///
/// # Panics
/// When the shipped alias file is malformed (a unit test keeps it parsing).
#[must_use]
pub fn vendor_name(name: &str) -> String {
    static ALIAS_MAP: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    let aliases = ALIAS_MAP.get_or_init(|| {
        let file: serde_json::Value =
            serde_json::from_str(ALIASES).expect("data/vendor-aliases.json parses");
        file["aliases"]
            .as_object()
            .expect("vendor-aliases.json has aliases")
            .iter()
            .filter_map(|(from, to)| Some((from.clone(), to.as_str()?.to_owned())))
            .collect()
    });
    let name = name.trim().to_ascii_lowercase();
    let name = name.trim_start_matches('~');
    aliases
        .get(name)
        .cloned()
        .unwrap_or_else(|| name.to_owned())
}

#[derive(Debug, Deserialize)]
struct SnapshotFile {
    #[allow(dead_code)]
    fields: Vec<String>,
    models: Vec<SnapshotModel>,
}

#[derive(Debug)]
struct Snapshot {
    models: Vec<SnapshotModel>,
    by_name: BTreeMap<String, Vec<usize>>,
}

impl Snapshot {
    /// Rows are positional arrays (`fields`); serde reads them as structs.
    fn parse(text: &str) -> Result<Self, serde_json::Error> {
        let file: SnapshotFile = serde_json::from_str(text)?;
        let mut by_name = BTreeMap::<String, Vec<usize>>::new();
        for (index, row) in file.models.iter().enumerate() {
            by_name.entry(name_key(&row.id)).or_default().push(index);
        }
        Ok(Self {
            models: file.models,
            by_name,
        })
    }

    /// The row for `model`: the named provider's (`provider/model`), else the
    /// one its vendor serves itself, else the first.
    fn lookup(&self, model: &str) -> Option<&SnapshotModel> {
        let rows = self.by_name.get(&name_key(model))?;
        let rows = rows.iter().map(|index| &self.models[*index]);
        let provider = model
            .trim()
            .split_once('/')
            .map(|(provider, _)| provider.to_ascii_lowercase());
        let rows = rows.collect::<Vec<_>>();
        rows.iter()
            .find(|row| provider.as_deref() == Some(row.provider.as_str()))
            .or_else(|| rows.iter().find(|row| row.first_party()))
            .or_else(|| rows.iter().find(|row| !row.vendor.is_empty()))
            .or_else(|| rows.first())
            .copied()
    }
}

fn snapshot() -> &'static Snapshot {
    static SNAPSHOT_INDEX: OnceLock<Snapshot> = OnceLock::new();
    SNAPSHOT_INDEX.get_or_init(|| Snapshot::parse(SNAPSHOT).expect("data/models-dev.json parses"))
}

fn valid_vendor(vendor: &str) -> Result<(), String> {
    if vendor.is_empty()
        || vendor.len() > 64
        || !vendor.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
    {
        return Err(format!(
            "vendor {vendor:?} is 1-64 lowercase letters, digits, `-`, `_` or `.`"
        ));
    }
    Ok(())
}

/// A model id `task(model)` may pass to an agent's model option.
///
/// # Errors
/// Returns why `model` is not one.
pub fn valid_model(model: &str) -> Result<(), String> {
    if model.is_empty()
        || model.len() > MAX_NAME_BYTES
        || model.starts_with('-')
        || !model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/@[]".contains(&byte))
    {
        return Err(format!(
            "model {model:?} is 1-128 letters, digits and `-_.:/@[]`, not starting with `-`"
        ));
    }
    Ok(())
}

/// One drop-in file (`docs/peer-review.md`).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DropIn {
    /// The schema version: 1 (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// `true` asks for peer review; `false` in any file turns it off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviewers: Vec<DropInReviewer>,
}

/// One ready pairing: `agent` can run `model` (its vendor's credentials are
/// in place). `class` and `vendor` default to the model's classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DropInReviewer {
    pub agent: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<ModelClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// `true` lets a model marsh's table does not curate (retired, or named
    /// by no rule) review anyway. Without it such a reviewer is skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_uncurated: Option<bool>,
}

impl DropIn {
    /// Parse and validate one drop-in.
    ///
    /// # Errors
    /// Returns why the text is not a valid drop-in.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: Self = if text.trim().is_empty() {
            Self::default()
        } else {
            serde_yaml::from_str(text).map_err(|error| error.to_string())?
        };
        if file.version.is_some_and(|version| version != 1) {
            return Err("version: only 1 is supported".into());
        }
        if file.reviewers.len() > MAX_REVIEWERS {
            return Err(format!("at most {MAX_REVIEWERS} reviewers per file"));
        }
        for (index, reviewer) in file.reviewers.iter().enumerate() {
            let at = |error: String| format!("reviewers[{index}]: {error}");
            marsh_contracts::command_registry::CommandName::parse(reviewer.agent.clone())
                .map_err(|error| at(format!("agent: {error}")))?;
            valid_model(&reviewer.model).map_err(at)?;
            if let Some(vendor) = &reviewer.vendor {
                valid_vendor(vendor).map_err(at)?;
            }
        }
        Ok(file)
    }

    /// The YAML `marsh config peer-review` writes.
    ///
    /// # Panics
    /// Never: the document always serializes.
    #[must_use]
    pub fn render(&self, comment: &str) -> String {
        let mut text = String::new();
        for line in comment.lines() {
            let _ = writeln!(text, "# {line}");
        }
        text.push_str(&serde_yaml::to_string(self).expect("drop-in serializes"));
        text
    }
}

/// One reviewer in the effective table.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reviewer {
    pub class: ModelClass,
    pub vendor: String,
    pub agent: String,
    pub model: String,
    /// The drop-in that named it.
    pub source: PathBuf,
    /// Where class and vendor came from: `declared` or the classification.
    pub classified: String,
    /// Why it is not ready (only in `skipped`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `marsh status` `peer_review`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeerReviewStatus {
    /// A drop-in says `enabled: true` and none says `enabled: false`.
    pub enabled: bool,
    /// The drop-ins read, in name order.
    #[serde(default)]
    pub files: Vec<PathBuf>,
    /// Drop-ins that say `enabled: false`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_by: Vec<PathBuf>,
    /// Ready reviewers, by class then vendor.
    #[serde(default)]
    pub reviewers: Vec<Reviewer>,
    /// Named but not ready, each with its reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<Reviewer>,
    /// Files (or the class override) that failed validation; a failing
    /// file contributes nothing.
    #[serde(default)]
    pub errors: Vec<String>,
}

/// What marsh knows about one registered agent.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentFacts {
    /// Its Kit declares non-interactive prompt verbs (`agent-sessions@1`
    /// `prompt`): `task` can start it.
    pub prompt: bool,
    /// Its Kit declares a model option (`org.marsh/agent-model@1`).
    pub model_option: bool,
    /// Its Kit declares itself multi-provider (`services: ["*"]`): it can use
    /// a vendor's models only where `reaches` says its Kit can.
    pub multi_provider: bool,
    /// Per credential service, the hosts its Kit allows and injects that
    /// service's key for.
    pub reaches: BTreeMap<String, BTreeSet<String>>,
}

/// Read `$MARSH_HOME/peer-review.d/*.yaml` and the class table and resolve
/// the effective reviewers against the registered agents.
#[must_use]
pub fn load(scope: &Path, agents: &BTreeMap<String, AgentFacts>) -> PeerReviewStatus {
    let (table, table_error) = ClassTable::load(scope);
    let mut status = PeerReviewStatus::default();
    status.errors.extend(table_error);
    let directory = scope.join(DROPIN_DIR);
    let mut said_on = false;
    let mut seen = BTreeMap::<(String, String), PathBuf>::new();
    for path in dropin_files(&directory, &mut status.errors) {
        let file = match read_small(&path).and_then(|text| {
            DropIn::parse(&text.unwrap_or_default())
                .map_err(|error| format!("{}: {error}", path.display()))
        }) {
            Ok(file) => file,
            Err(error) => {
                status.errors.push(error);
                continue;
            }
        };
        status.files.push(path.clone());
        match file.enabled {
            Some(true) => said_on = true,
            Some(false) => status.disabled_by.push(path.clone()),
            None => {}
        }
        for entry in file.reviewers {
            let classified = table.classify(&entry.model);
            let eligible = classified.as_ref().is_some_and(|found| found.eligible);
            let declared = entry.class.is_some() && entry.vendor.is_some();
            let class = entry
                .class
                .or_else(|| classified.as_ref().and_then(|found| found.class));
            let vendor = entry
                .vendor
                .as_deref()
                .map(vendor_name)
                .or_else(|| classified.as_ref().and_then(|found| found.vendor.clone()));
            let mut reviewer = Reviewer {
                class: class.unwrap_or(ModelClass::Mid),
                vendor: vendor.clone().unwrap_or_default(),
                agent: entry.agent.clone(),
                model: entry.model.clone(),
                source: path.clone(),
                classified: if declared {
                    "declared".into()
                } else {
                    classified
                        .as_ref()
                        .map_or_else(|| "unknown".into(), |found| found.how.clone())
                },
                reason: None,
            };
            let key = (entry.agent.clone(), entry.model.to_ascii_lowercase());
            reviewer.reason = if !eligible && entry.allow_uncurated != Some(true) {
                Some(uncurated_reason(&entry.model, classified.as_ref()))
            } else if class.is_none() {
                Some(format!(
                    "marsh cannot class {}: add `class` and `vendor`, or a rule in $MARSH_HOME/{OVERRIDE_FILE}",
                    entry.model
                ))
            } else if vendor.is_none() {
                Some(format!(
                    "marsh does not know who makes {} (models.dev names only hosts): add `vendor`",
                    entry.model
                ))
            } else if let Some(first) = seen.get(&key) {
                Some(format!("already named in {}", first.display()))
            } else {
                match agents.get(&entry.agent) {
                    None => Some(format!("{} is not a registered command", entry.agent)),
                    Some(facts) if !facts.prompt => Some(format!(
                        "{}'s Kit declares no prompt verbs (agent-sessions@1 `prompt`), so `task` cannot start it",
                        entry.agent
                    )),
                    Some(facts) if !facts.model_option => Some(format!(
                        "{}'s Kit declares no model option (org.marsh/agent-model@1)",
                        entry.agent
                    )),
                    Some(facts) if facts.multi_provider => {
                        cannot_reach(&entry.agent, &reviewer.vendor, &facts.reaches)
                    }
                    Some(_) => None,
                }
            };
            if reviewer.reason.is_some() {
                status.skipped.push(reviewer);
            } else {
                seen.insert(key, path.clone());
                status.reviewers.push(reviewer);
            }
        }
    }
    status.enabled = said_on && status.disabled_by.is_empty();
    status.reviewers.sort_by(|a, b| {
        (a.class, &a.vendor, &a.agent, &a.model).cmp(&(b.class, &b.vendor, &b.agent, &b.model))
    });
    status
}

fn uncurated_reason(model: &str, classified: Option<&Classified>) -> String {
    if classified.is_some_and(|found| found.how == RETIRED) {
        format!(
            "{model} is retired: marsh's table lists it as superseded and never uses it for peer review. Name a current model (`marsh peer-review classify MODEL`), or set `allow_uncurated: true` on this reviewer"
        )
    } else {
        format!(
            "{model} is not in marsh's curated model table, so marsh does not use it for peer review (`marsh peer-review classify {model}`). Add a rule in $MARSH_HOME/{OVERRIDE_FILE}, or set `allow_uncurated: true` on this reviewer"
        )
    }
}

/// `peer-review.d/*.yaml` (and `.yml`) in name order; dotfiles are skipped.
fn dropin_files(directory: &Path, errors: &mut Vec<String>) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            errors.push(format!("{}: {error}", directory.display()));
            return Vec::new();
        }
    };
    let mut names = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| {
            !name.starts_with('.')
                && (name.strip_suffix(".yaml").is_some() || name.strip_suffix(".yml").is_some())
        })
        .collect::<Vec<_>>();
    names.sort();
    if names.len() > MAX_FILES {
        errors.push(format!(
            "{}: only the first {MAX_FILES} drop-ins are read",
            directory.display()
        ));
        names.truncate(MAX_FILES);
    }
    names.into_iter().map(|name| directory.join(name)).collect()
}

/// A small regular file's text; `None` when it does not exist.
fn read_small(path: &Path) -> Result<Option<String>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if !metadata.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(format!("{}: over {MAX_FILE_BYTES} bytes", path.display()));
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// The section appended to a job's `context.md` while peer review is on:
/// the instruction and the ready reviewers this job may start. Empty when
/// peer review is off or no reviewer is in the job's spawn set.
#[must_use]
pub fn context(status: &PeerReviewStatus, spawn: &[String]) -> String {
    if !status.enabled {
        return String::new();
    }
    // One reviewer per class and vendor (the first, in table order), at
    // most CONTEXT_ROWS rows: the section stays short.
    let mut seen = BTreeSet::new();
    let rows = status
        .reviewers
        .iter()
        .filter(|reviewer| spawn.contains(&reviewer.agent))
        .filter(|reviewer| seen.insert((reviewer.class, reviewer.vendor.clone())))
        .take(CONTEXT_ROWS)
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return String::new();
    }
    let mut text = String::from(
        "## Peer review: required before your final answer\n\
         Before you report substantial work as done, get a review: call the marsh `task` tool \
         with the agent and model of the row below for your own model's class whose vendor is \
         not your model's, `description: \"peer review\"`, and a prompt that says what to \
         review and asks for findings only, changing no files (e.g. \"Review the uncommitted \
         changes in this folder for bugs, missed cases and missing tests\", or the plan or \
         document itself). Substantial means, e.g., a code change beyond a trivial edit (new \
         behavior, a bug fix, a refactor, anything with tests), a plan or design, an analysis \
         someone will act on, a document the user will send. Not for quick answers, typo or \
         one-line fixes, or pure lookups. Then fix what it finds, or tell the user which \
         findings you left and why. No row for your class from another vendor: skip it.\n\
         Classes: small (claude-haiku, gpt-luna, gemini-flash), mid (claude-sonnet, gpt-terra, \
         gemini-pro), large (claude-opus, claude-fable, gpt-sol, gpt-astra).\n\n\
         | class | vendor | task arguments |\n|---|---|---|\n",
    );
    for reviewer in rows {
        let _ = writeln!(
            text,
            "| {} | {} | agent: \"{}\", model: \"{}\" |",
            reviewer.class.name(),
            reviewer.vendor,
            reviewer.agent,
            reviewer.model
        );
    }
    text
}

/// The service a multi-provider agent's Kit declares (`org.marsh/agent-model@1`
/// `services`): it reaches every vendor whose key the host holds.
pub use marsh_contracts::kit_assets::ANY_PROVIDER;

/// The API host of each vendor whose key a multi-provider agent's Kit might
/// carry; a credential service is named for its vendor (`sbx secret ls`).
const VENDOR_HOSTS: [(&str, &str); 6] = [
    ("anthropic", "api.anthropic.com"),
    ("openai", "api.openai.com"),
    ("google", "generativelanguage.googleapis.com"),
    ("mistral", "api.mistral.ai"),
    ("xai", "api.x.ai"),
    ("deepseek", "api.deepseek.com"),
];

/// Why a multi-provider `agent` cannot use `vendor`'s models: its Kit must
/// allow the vendor's API host and inject the vendor's key for it
/// (`reaches`, per credential service).
fn cannot_reach(
    agent: &str,
    vendor: &str,
    reaches: &BTreeMap<String, BTreeSet<String>>,
) -> Option<String> {
    let Some((_, host)) = VENDOR_HOSTS.iter().find(|(name, _)| *name == vendor) else {
        return Some(format!(
            "{agent} can't reach {vendor}: marsh does not know its API host"
        ));
    };
    (!reaches
        .get(vendor)
        .is_some_and(|hosts| hosts.contains(*host)))
    .then(|| {
        format!(
            "{agent} can't reach {host} (its Kit must allow the host and inject the {vendor} key for it)"
        )
    })
}

/// A registered agent as `marsh config peer-review on` sees it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DetectAgent {
    /// Its Kit's credential services, `"*"` for a multi-provider agent.
    pub services: BTreeSet<String>,
    /// Per credential service, the hosts its Kit allows and injects that
    /// service's key for.
    pub reaches: BTreeMap<String, BTreeSet<String>>,
}

/// What detection found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Detected {
    /// Reviewers marsh can start, by class then vendor.
    pub ready: Vec<DropInReviewer>,
    /// Vendors whose key the host holds, with no agent that reaches them
    /// except a multi-provider one whose Kit cannot (the reason says why).
    /// `marsh peer-review ls` lists them as not ready.
    pub unreachable: Vec<(DropInReviewer, String)>,
}

/// The reviewers `marsh config peer-review on` offers: for each class and
/// each vendor an agent with a model option can reach with a stored
/// credential, the vendor's newest model in that class. A vendor's own
/// agent (one that reaches only it) is preferred. A multi-provider agent
/// (services `["*"]`) is the last resort, takes the provider-qualified id
/// (`openai/gpt-6.1-terra`), and counts for a vendor only where its Kit
/// allows the vendor's API host and injects its key.
#[must_use]
pub fn detect(
    table: &ClassTable,
    agents: &BTreeMap<String, DetectAgent>,
    credentials: &BTreeSet<String>,
) -> Detected {
    let mut chosen = BTreeMap::<(ModelClass, String), (usize, String, bool)>::new();
    let mut blocked = BTreeMap::<(ModelClass, String), (String, String)>::new();
    for (agent, facts) in agents {
        let any = facts.services.contains(ANY_PROVIDER);
        for vendor in credentials
            .iter()
            .filter(|vendor| any || facts.services.contains(*vendor))
        {
            let named = facts.services.contains(vendor);
            let refusal = if any {
                cannot_reach(agent, vendor, &facts.reaches)
            } else {
                None
            };
            let rank = if named {
                facts.services.len()
            } else {
                usize::MAX
            };
            for class in ModelClass::ALL {
                if table.newest(vendor, class).is_none() {
                    continue;
                }
                let key = (class, vendor.clone());
                if let Some(reason) = &refusal {
                    blocked
                        .entry(key)
                        .or_insert_with(|| (agent.clone(), reason.clone()));
                } else if chosen.get(&key).is_none_or(|(best, _, _)| rank < *best) {
                    chosen.insert(key, (rank, agent.clone(), any));
                }
            }
        }
    }
    let reviewer = |class: ModelClass, vendor: &str, agent: String, qualified: bool| {
        let newest = table.newest(vendor, class)?;
        Some(DropInReviewer {
            model: if qualified {
                format!("{vendor}/{newest}")
            } else {
                newest
            },
            agent,
            class: Some(class),
            vendor: Some(vendor.to_owned()),
            allow_uncurated: None,
        })
    };
    Detected {
        unreachable: blocked
            .into_iter()
            .filter(|(key, _)| !chosen.contains_key(key))
            .filter_map(|((class, vendor), (agent, reason))| {
                Some((reviewer(class, &vendor, agent, true)?, reason))
            })
            .collect(),
        ready: chosen
            .into_iter()
            .filter_map(|((class, vendor), (_, agent, qualified))| {
                reviewer(class, &vendor, agent, qualified)
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(table: &ClassTable, model: &str) -> Option<(ModelClass, String)> {
        table
            .classify(model)
            .map(|found| (found.class.unwrap(), found.vendor.unwrap_or_default()))
    }

    /// One snapshot row: provider, id, family, vendor, output price, released.
    type Row = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        f64,
        &'static str,
    );

    /// A row released `days` after the newest release of the snapshot it is
    /// added to, so no real model a refresh brings can be newer than it.
    type Later = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        f64,
        i64,
    );

    fn table_over(models: &[serde_json::Value]) -> ClassTable {
        let text = serde_json::json!({"fields": [], "models": models}).to_string();
        ClassTable::with_snapshot(Snapshot::parse(&text).unwrap())
    }

    fn rows(extra: &[Row]) -> Vec<serde_json::Value> {
        extra
            .iter()
            .map(|(provider, id, family, vendor, output, released)| {
                serde_json::json!([provider, id, family, vendor, output, false, released])
            })
            .collect()
    }

    /// Days since 1970-01-01 of a calendar date, and back (proleptic
    /// Gregorian, Howard Hinnant's algorithms).
    fn civil_days(year: i64, month: i64, day: i64) -> i64 {
        let year = year - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    fn civil_date(days: i64) -> (i64, i64, i64) {
        let days = days + 719_468;
        let era = days.div_euclid(146_097);
        let day_of_era = days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = if month_index < 10 {
            month_index + 3
        } else {
            month_index - 9
        };
        (year_of_era + era * 400 + i64::from(month <= 2), month, day)
    }

    fn add_days(date: &str, days: i64) -> String {
        let [year, month, day]: [i64; 3] = date
            .split('-')
            .map(|part| part.parse().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let (year, month, day) = civil_date(civil_days(year, month, day) + days);
        format!("{year:04}-{month:02}-{day:02}")
    }

    #[test]
    fn the_test_calendar_adds_days() {
        assert_eq!(add_days("2026-12-16", 0), "2026-12-16");
        assert_eq!(add_days("2026-12-16", 30), "2027-01-15");
        assert_eq!(add_days("2028-02-28", 1), "2028-02-29");
        assert_eq!(add_days("2099-01-01", 400), "2100-02-05");
        assert_eq!(add_days("2026-03-01", -1), "2026-02-28");
    }

    /// The compiled-in snapshot with models a refresh may bring: `fixed` rows
    /// as dated, then `later` rows dated after the newest release of all of
    /// it (so they stay the newest, whatever a real refresh adds). The product
    /// code must take them in its stride.
    fn builtin_plus(fixed: &[Row], later: &[Later]) -> ClassTable {
        let mut file: serde_json::Value = serde_json::from_str(SNAPSHOT).unwrap();
        let models = file["models"].as_array_mut().unwrap();
        models.extend(rows(fixed));
        let latest = models
            .iter()
            .filter_map(|row| row[6].as_str())
            .max()
            .unwrap()
            .to_owned();
        for (provider, id, family, vendor, output, days) in later {
            let released = add_days(&latest, *days);
            models.push(serde_json::json!([
                provider, id, family, vendor, output, false, released
            ]));
        }
        let table = ClassTable::with_snapshot(Snapshot::parse(&file.to_string()).unwrap());
        assert_eq!(
            table.snapshot.models.len(),
            snapshot().models.len() + fixed.len() + later.len()
        );
        table
    }

    type Families = [(&'static str, ModelClass); 4];

    /// The families of the two vendors' agents (`family_nickname` of each
    /// rule), with the class the curated table gives each.
    const FAMILIES: [(&str, &str, Families); 2] = [
        (
            "codex",
            "openai",
            [
                ("luna", ModelClass::Small),
                ("terra", ModelClass::Mid),
                ("sol", ModelClass::Large),
                ("astra", ModelClass::Large),
            ],
        ),
        (
            "claude",
            "anthropic",
            [
                ("haiku", ModelClass::Small),
                ("sonnet", ModelClass::Mid),
                ("fable", ModelClass::Large),
                ("opus", ModelClass::Large),
            ],
        ),
    ];

    /// The oracle below counts release distances the way the product
    /// documents (`day_number`: 365-day years of 31-day months) and cuts at
    /// the literal 180, written here and not taken from the product.
    const OWN_RECENT_DAYS: i64 = 180;

    fn own_days(date: &str) -> i64 {
        let [year, month, day]: [i64; 3] = date
            .split('-')
            .map(|part| part.parse().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        year * 372 + month * 31 + day
    }

    /// `model`'s release date as the vendor itself lists it (the newest, where
    /// a snapshot repeats an id).
    fn released(table: &ClassTable, model: &str) -> String {
        table
            .snapshot
            .models
            .iter()
            .filter(|row| row.id == model && row.provider == row.vendor)
            .map(|row| row.released.clone())
            .max()
            .unwrap_or_else(|| panic!("{model} is not in the snapshot"))
    }

    /// The newest models of `families` that `vendor` itself lists, read off
    /// the table's snapshot by release date, a shorter id winning a tie: ALL
    /// the models tied for it. The product keeps whichever tied row comes
    /// first, which is no promise, so a test accepts any member of the set.
    /// Written without the product's `first_party`, `normalize` and
    /// `day_number`; only `plain_chat_model` (which ids are chat models) is
    /// shared. It knows nothing of retired models, so only a snapshot where no
    /// retired model is newer than a current one may use it.
    fn newest_models(table: &ClassTable, vendor: &str, families: &[&str]) -> Vec<String> {
        let needles = families.iter().map(|f| format!("-{f}")).collect::<Vec<_>>();
        let rows = table
            .snapshot
            .models
            .iter()
            .filter(|row| row.vendor == vendor && row.provider == vendor)
            .filter(|row| plain_chat_model(&row.id))
            .filter(|row| {
                let id = row.id.to_ascii_lowercase();
                needles.iter().any(|needle| id.contains(needle))
            })
            .map(|row| {
                (
                    row.released.clone(),
                    std::cmp::Reverse(row.id.len()),
                    &row.id,
                )
            })
            .collect::<Vec<_>>();
        let Some(best) = rows.iter().map(|(released, len, _)| (released, len)).max() else {
            return Vec::new();
        };
        let mut tied = rows
            .iter()
            .filter(|(released, len, _)| (released, len) == best)
            .map(|(_, _, id)| (*id).clone())
            .collect::<Vec<_>>();
        tied.sort();
        tied.dedup();
        tied
    }

    /// One family the `task` tool should list.
    #[derive(Debug)]
    struct Expected {
        family: String,
        class: ModelClass,
        released: String,
        /// Any of these is a correct row (tied for the family's newest).
        models: Vec<String>,
    }

    /// What the `task` tool lists for `vendor`'s own agent: each family's
    /// newest model, except a family more than `OWN_RECENT_DAYS` behind the
    /// vendor's newest; small before mid before large, newest first within a
    /// class (the order of families released on one day is not promised).
    fn expected_list(
        table: &ClassTable,
        vendor: &str,
        families: &[(&str, ModelClass)],
    ) -> Vec<Expected> {
        let found = families
            .iter()
            .filter_map(|(family, class)| {
                let models = newest_models(table, vendor, &[family]);
                let released = released(table, models.first()?);
                Some(Expected {
                    family: (*family).to_owned(),
                    class: *class,
                    released,
                    models,
                })
            })
            .collect::<Vec<_>>();
        let latest = found
            .iter()
            .map(|e| own_days(&e.released))
            .max()
            .unwrap_or(0);
        let mut found = found
            .into_iter()
            .filter(|e| own_days(&e.released) + OWN_RECENT_DAYS >= latest)
            .collect::<Vec<_>>();
        found.sort_by_key(|e| {
            (
                e.class,
                std::cmp::Reverse(e.released.clone()),
                e.family.clone(),
            )
        });
        found
    }

    #[test]
    fn the_curated_table_pairs_the_vendors_families() {
        let table = ClassTable::builtin();
        let small = ModelClass::Small;
        let mid = ModelClass::Mid;
        let large = ModelClass::Large;
        for (model, expected, vendor) in [
            ("claude-haiku-5-5", small, "anthropic"),
            ("gpt-6-luna", small, "openai"),
            ("claude-sonnet-5-5", mid, "anthropic"),
            ("sonnet", mid, "anthropic"),
            ("gpt-6.1-terra", mid, "openai"),
            ("openai/gpt-6.1-terra", mid, "openai"),
            ("us.anthropic.claude-sonnet-5-5-v1:0", mid, "anthropic"),
            ("claude-fable-5-1", large, "anthropic"),
            ("gpt-6-astra", large, "openai"),
            ("claude-opus-5-5", large, "anthropic"),
            ("gpt-6.1-sol", large, "openai"),
            ("gemini-3.8-flash", small, "google"),
            ("gemini-3.1-pro-preview", mid, "google"),
            ("deepseek-v4-flash", small, "deepseek"),
            ("qwen3.8-max", large, "alibaba"),
            ("glm-5.3", mid, "zai"),
            ("kimi-k2.6", mid, "moonshotai"),
        ] {
            assert_eq!(
                class(&table, model),
                Some((expected, vendor.to_owned())),
                "{model}"
            );
        }
        // A family rule reaches an id the patterns do not name.
        let found = table.classify("gpt-daybreak-blue-latest").unwrap();
        assert_eq!(
            (found.class, found.vendor.as_deref()),
            (Some(large), Some("openai"))
        );
        assert!(found.eligible);
        assert!(
            found.how.starts_with("models.dev family gpt-sol"),
            "{}",
            found.how
        );
    }

    #[test]
    fn the_override_comes_first_and_can_move_the_bands() {
        let scope = tempfile::tempdir().unwrap();
        std::fs::write(
            scope.path().join(OVERRIDE_FILE),
            "bands: {small_below: 1, large_from: 3}\n\
             rules:\n  - {match: \"gpt-*sol*\", class: mid, vendor: openai}\n",
        )
        .unwrap();
        let (table, error) = ClassTable::load(scope.path());
        assert_eq!(error, None);
        let found = table.classify("gpt-6.1-sol").unwrap();
        assert_eq!(found.class, Some(ModelClass::Mid));
        assert_eq!(found.how, "$MARSH_HOME/model-classes.yaml: gpt-*sol*");
        // An unnamed model moves with the bands: grok-4.7 lists $6/M output.
        assert_eq!(
            table.classify("grok-4.7").unwrap().class,
            Some(ModelClass::Large)
        );
        // A malformed override is reported and marsh's table still applies.
        std::fs::write(scope.path().join(OVERRIDE_FILE), "rules: [{match: x}]").unwrap();
        let (table, error) = ClassTable::load(scope.path());
        assert!(error.unwrap().contains("model-classes.yaml"));
        assert_eq!(
            table.classify("gpt-6.1-sol").unwrap().class,
            Some(ModelClass::Large)
        );
    }

    #[test]
    fn the_override_can_retire_a_model_or_revive_a_retired_one() {
        let scope = tempfile::tempdir().unwrap();
        std::fs::write(
            scope.path().join(OVERRIDE_FILE),
            "retired: [\"claude-opus-5\"]\n\
             rules:\n  - {match: \"o3*\", class: large, vendor: openai}\n",
        )
        .unwrap();
        let (table, error) = ClassTable::load(scope.path());
        assert_eq!(error, None);
        assert!(!table.classify("claude-opus-5").unwrap().eligible);
        assert!(table.classify("claude-opus-5-5").unwrap().eligible);
        let revived = table.classify("o3-pro").unwrap();
        assert!(revived.eligible, "{revived:?}");
        assert!(
            ClassTable::builtin()
                .classify("claude-opus-5")
                .unwrap()
                .eligible
        );
        std::fs::write(scope.path().join(OVERRIDE_FILE), "retired: ['']").unwrap();
        assert!(ClassTable::load(scope.path()).1.is_some());
    }

    #[test]
    fn unnamed_models_fall_back_to_their_price_band_and_unknown_ones_to_none() {
        let table = ClassTable::builtin();
        // xAI has no rule: $6/M output is mid; the maker is the vendor.
        let found = table.classify("grok-4.7").unwrap();
        assert_eq!(
            (found.class, found.vendor.as_deref()),
            (Some(ModelClass::Mid), Some("xai"))
        );
        assert_eq!(found.how, "models.dev price $6/M output");
        // Price classes it for display, but nothing marsh does by itself uses it.
        assert!(!found.eligible);
        // Meta's Muse Wonder lists $20/M output: large.
        assert_eq!(
            class(&table, "muse-wonder-1.0"),
            Some((ModelClass::Large, "meta".into()))
        );
        assert_eq!(table.bands().class(0.5), ModelClass::Small);
        assert_eq!(table.classify("no-such-model-anywhere"), None);
        assert_eq!(table.classify(""), None);
    }

    #[test]
    fn a_model_has_its_makers_vendor_on_every_host() {
        let table = ClassTable::builtin();
        // Hosts spell the maker differently (`x-ai`, `xai`) or name none.
        for model in [
            "fastrouter/x-ai/grok-4",
            "llmgateway-providers/xai/grok-4",
            "xai/grok-4",
            "grok-4",
        ] {
            assert_eq!(
                class(&table, model),
                Some((ModelClass::Mid, "xai".into())),
                "{model}"
            );
        }
        assert_eq!(
            class(&table, "venice/grok-4-6"),
            class(&table, "xai/grok-4.6")
        );
        // Muse on a host is still Meta's, never the host's.
        for model in [
            "venice/muse-wonder",
            "kilo/meta/muse-wonder",
            "meta/muse-wonder-1.0",
        ] {
            assert_eq!(
                class(&table, model).map(|found| found.1),
                Some("meta".into()),
                "{model}"
            );
        }
        // No maker anywhere: classed by price, but no vendor to pair.
        let found = table.classify("abliteration-ai/abliterated-model").unwrap();
        assert_eq!(found.vendor, None, "{found:?}");
        assert_eq!(vendor_name("~X-AI"), "xai");
        assert_eq!(vendor_name("zhipuai"), "zai");
        assert_eq!(vendor_name("openai"), "openai");
    }

    /// Models a real refresh could bring, dated as it could: a newer opus and
    /// sonnet within weeks, and a model far in the future. Every table built
    /// on them must still pass every test, which is the point of them.
    #[rustfmt::skip]
    const A_REFRESH: [Row; 3] = [
        ("anthropic", "claude-opus-5-6", "claude-opus", "anthropic", 20.0, "2026-12-20"),
        ("anthropic", "claude-sonnet-5-6", "claude-sonnet", "anthropic", 10.0, "2027-01-10"),
        ("openai", "gpt-6.2-sol", "gpt-sol", "openai", 10.0, "2099-01-01"),
    ];

    /// A newer fable a month on from the snapshot's newest release.
    #[rustfmt::skip]
    const FABLE_A_MONTH_ON: Later = ("anthropic", "claude-fable-x9", "claude-fable", "anthropic", 40.0, 30);

    /// A fable so much newer than the vendor's other families that they fall
    /// out of the `task` tool's list (a family over half a year behind).
    #[rustfmt::skip]
    const FABLE_A_YEAR_ON: Later = ("anthropic", "claude-fable-x9", "claude-fable", "anthropic", 40.0, 400);

    /// A newer model in every family, the vendor's large families in the
    /// opposite order to today's (opus and sol newest), a year on.
    #[rustfmt::skip]
    const EVERY_FAMILY_NEWER: [Later; 8] = [
        ("anthropic", "claude-haiku-x9", "claude-haiku", "anthropic", 0.5, 401),
        ("anthropic", "claude-sonnet-x9", "claude-sonnet", "anthropic", 10.0, 402),
        ("anthropic", "claude-fable-x9", "claude-fable", "anthropic", 40.0, 403),
        ("anthropic", "claude-opus-x9", "claude-opus", "anthropic", 20.0, 404),
        ("openai", "gpt-x9-luna", "gpt-luna", "openai", 0.5, 401),
        ("openai", "gpt-x9-terra", "gpt-terra", "openai", 5.0, 402),
        ("openai", "gpt-x9-astra", "gpt-astra", "openai", 50.0, 403),
        ("openai", "gpt-x9-sol", "gpt-sol", "openai", 10.0, 404),
    ];

    /// The compiled-in snapshot, and it with the models a refresh may bring,
    /// alone and on top of `A_REFRESH`. Every test of what is newest and how
    /// it is listed runs on each.
    fn refreshed_tables() -> Vec<(String, ClassTable)> {
        let mut tables = Vec::new();
        for (base, fixed) in [("", &[][..]), (" after a refresh", &A_REFRESH[..])] {
            tables.push((
                format!("compiled-in snapshot{base}"),
                builtin_plus(fixed, &[]),
            ));
            tables.push((
                format!("a newer fable{base}"),
                builtin_plus(fixed, &[FABLE_A_MONTH_ON]),
            ));
            tables.push((
                format!("a fable a year on{base}"),
                builtin_plus(fixed, &[FABLE_A_YEAR_ON]),
            ));
            tables.push((
                format!("every family newer{base}"),
                builtin_plus(fixed, &EVERY_FAMILY_NEWER),
            ));
        }
        tables
    }

    /// Models no listing may reach for, though they are newer than every
    /// current model: retired generations, ids that are not plain chat models,
    /// and another host's listing of a maker's model.
    #[rustfmt::skip]
    const NEWER_BUT_NEVER_OFFERED: [Later; 8] = [
        ("anthropic", "claude-opus-4-9", "claude-opus", "anthropic", 25.0, 900),
        ("anthropic", "claude-sonnet-4-9", "claude-sonnet", "anthropic", 15.0, 900),
        ("anthropic", "claude-haiku-5-9-preview", "claude-haiku", "anthropic", 0.5, 900),
        ("anthropic", "claude-haiku-5-9-20320101", "claude-haiku", "anthropic", 0.5, 900),
        ("openai", "gpt-5.9", "gpt-5", "openai", 10.0, 900),
        ("openai", "gpt-6.3-terra-latest", "gpt-terra", "openai", 5.0, 900),
        ("openai", "gpt-6.3-luna-codex", "gpt-luna", "openai", 0.5, 900),
        ("openrouter", "anthropic/claude-opus-7-9", "claude-opus", "anthropic", 20.0, 900),
    ];

    #[test]
    fn newest_picks_the_vendors_current_model_in_a_class() {
        for (what, table) in refreshed_tables() {
            for (_, vendor, families) in FAMILIES {
                for class in ModelClass::ALL {
                    let in_class = families
                        .iter()
                        .filter(|(_, family_class)| *family_class == class)
                        .map(|(family, _)| *family)
                        .collect::<Vec<_>>();
                    let named = newest_models(&table, vendor, &in_class);
                    assert!(
                        !named.is_empty(),
                        "{what}: no {vendor} {class:?} in the snapshot"
                    );
                    let newest = table.newest(vendor, class);
                    assert!(
                        newest.as_ref().is_some_and(|model| named.contains(model)),
                        "{what}: {vendor} {class:?}: {newest:?} is not one of {named:?}"
                    );
                }
            }
        }
        // The expectation moves with the snapshot: a model added to it is the
        // answer, and the product does not go on naming the one it replaced.
        for fixed in [&[][..], &A_REFRESH[..]] {
            let table = builtin_plus(fixed, &[FABLE_A_MONTH_ON]);
            assert_eq!(
                table.newest("anthropic", ModelClass::Large).as_deref(),
                Some("claude-fable-x9")
            );
            let table = builtin_plus(fixed, &EVERY_FAMILY_NEWER);
            for (vendor, class, model) in [
                ("anthropic", ModelClass::Small, "claude-haiku-x9"),
                ("anthropic", ModelClass::Mid, "claude-sonnet-x9"),
                ("anthropic", ModelClass::Large, "claude-opus-x9"),
                ("openai", ModelClass::Small, "gpt-x9-luna"),
                ("openai", ModelClass::Mid, "gpt-x9-terra"),
                ("openai", ModelClass::Large, "gpt-x9-sol"),
            ] {
                assert_eq!(table.newest(vendor, class).as_deref(), Some(model));
            }
        }
    }

    fn agents(entries: &[(&str, bool)]) -> BTreeMap<String, AgentFacts> {
        entries
            .iter()
            .map(|(name, model_option)| {
                (
                    (*name).to_owned(),
                    AgentFacts {
                        prompt: *name != "shell",
                        model_option: *model_option,
                        ..AgentFacts::default()
                    },
                )
            })
            .collect()
    }

    #[test]
    fn dropins_resolve_to_ready_reviewers_and_say_why_others_are_not() {
        let scope = tempfile::tempdir().unwrap();
        let directory = scope.path().join(DROPIN_DIR);
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("narwhal.yaml"),
            "enabled: true\nreviewers:\n\
             - {agent: codex, model: gpt-6.1-terra}\n\
             - {agent: claude, model: claude-sonnet-5-5}\n\
             - {agent: pi, model: claude-opus-5-5}\n\
             - {agent: hermes, model: gpt-6-astra}\n\
             - {agent: shell, model: gpt-6-astra}\n\
             - {agent: codex, model: my-house-model, allow_uncurated: true}\n\
             - {agent: codex, model: my-house-model, class: large, vendor: openai, allow_uncurated: true}\n\
             - {agent: codex, model: abliteration-ai/abliterated-model, allow_uncurated: true}\n\
             - {agent: claude, model: x-ai/grok-4, vendor: x-ai, allow_uncurated: true}\n\
             - {agent: codex, model: grok-4, vendor: xai, allow_uncurated: true}\n",
        )
        .unwrap();
        std::fs::write(directory.join("broken.yaml"), "enabled: maybe\n").unwrap();
        std::fs::write(directory.join(".swap.yaml"), "not: [yaml").unwrap();
        let known = agents(&[
            ("claude", true),
            ("codex", true),
            ("pi", false),
            ("shell", false),
        ]);
        let status = load(scope.path(), &known);
        assert!(status.enabled);
        assert_eq!(status.files, [directory.join("narwhal.yaml")]);
        assert_eq!(status.errors.len(), 1, "{:?}", status.errors);
        assert!(status.errors[0].contains("broken.yaml"));
        let ready = status
            .reviewers
            .iter()
            .map(|r| {
                (
                    r.class.name(),
                    r.vendor.as_str(),
                    r.agent.as_str(),
                    r.model.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ready,
            [
                ("mid", "anthropic", "claude", "claude-sonnet-5-5"),
                ("mid", "openai", "codex", "gpt-6.1-terra"),
                // An explicit vendor alias is canonical too.
                ("mid", "xai", "claude", "x-ai/grok-4"),
                ("mid", "xai", "codex", "grok-4"),
                ("large", "openai", "codex", "my-house-model"),
            ]
        );
        let reasons = status
            .skipped
            .iter()
            .map(|r| r.reason.clone().unwrap())
            .collect::<Vec<_>>();
        assert!(
            reasons[0].contains("pi's Kit declares no model option"),
            "{reasons:?}"
        );
        assert!(reasons[1].contains("hermes is not a registered command"));
        assert!(reasons[2].contains("shell's Kit declares no prompt verbs"));
        assert!(reasons[3].contains("cannot class my-house-model"));
        assert!(
            reasons[4].contains("does not know who makes abliteration-ai/abliterated-model"),
            "{reasons:?}"
        );

        let text = context(&status, &["claude".into(), "codex".into()]);
        assert!(text.starts_with("## Peer review: required before your final answer\n"));
        assert!(text.contains("| mid | openai | agent: \"codex\", model: \"gpt-6.1-terra\" |"));
        // Two reviewers of one class and vendor: only the first is shown.
        assert_eq!(text.matches("| mid | xai |").count(), 1);
        let only_claude = context(&status, &["claude".into()]);
        assert!(!only_claude.contains("codex"));
        assert_eq!(context(&status, &[]), "");

        // `enabled: false` anywhere turns it off.
        std::fs::write(directory.join("marsh.yaml"), "enabled: false\n").unwrap();
        let status = load(scope.path(), &known);
        assert!(!status.enabled);
        assert_eq!(status.disabled_by, [directory.join("marsh.yaml")]);
        assert_eq!(context(&status, &["codex".into()]), "");
    }

    #[test]
    fn dropins_are_validated() {
        for (text, error) in [
            ("version: 2\n", "version"),
            ("colour: blue\n", "unknown field"),
            ("reviewers: [{agent: codex}]\n", "missing field `model`"),
            (
                "reviewers: [{agent: codex, model: '--yolo'}]\n",
                "not starting with `-`",
            ),
            ("reviewers: [{agent: 'Co dex', model: x}]\n", "agent"),
            (
                "reviewers: [{agent: codex, model: x, class: huge}]\n",
                "unknown variant",
            ),
            (
                "reviewers: [{agent: codex, model: x, vendor: OpenAI}]\n",
                "lowercase",
            ),
        ] {
            let found = DropIn::parse(text).unwrap_err();
            assert!(found.contains(error), "{text}: {found}");
        }
        assert_eq!(DropIn::parse("").unwrap(), DropIn::default());
    }

    fn set(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|v| (*v).to_owned()).collect()
    }

    fn agent(services: &[&str], reaches: &[(&str, &str)]) -> DetectAgent {
        let mut found = DetectAgent {
            services: set(services),
            reaches: BTreeMap::new(),
        };
        for (service, host) in reaches {
            found
                .reaches
                .entry((*service).to_owned())
                .or_default()
                .insert((*host).to_owned());
        }
        found
    }

    #[test]
    fn detect_prefers_each_vendors_own_agent() {
        let table = ClassTable::builtin();
        let agents = BTreeMap::from([
            ("claude".to_owned(), agent(&["anthropic"], &[])),
            ("codex".to_owned(), agent(&["openai"], &[])),
            (
                "pix".to_owned(),
                agent(&["anthropic", "openai", "google"], &[]),
            ),
        ]);
        let found = detect(&table, &agents, &set(&["anthropic", "openai"]));
        let mid = found
            .ready
            .iter()
            .filter(|r| r.class == Some(ModelClass::Mid))
            .map(|r| (r.agent.as_str(), r.model.as_str()))
            .collect::<Vec<_>>();
        let newest = |vendor| table.newest(vendor, ModelClass::Mid).unwrap();
        assert_eq!(
            mid,
            [
                ("claude", newest("anthropic").as_str()),
                ("codex", newest("openai").as_str())
            ]
        );
        assert!(!found.ready.iter().any(|r| r.agent == "pix"));
        let rendered = DropIn {
            version: Some(1),
            enabled: Some(true),
            reviewers: found.ready,
        }
        .render("written by marsh");
        assert!(DropIn::parse(&rendered).is_ok(), "{rendered}");
    }

    #[test]
    fn a_multi_provider_agent_counts_only_for_vendors_its_kit_reaches() {
        let table = ClassTable::builtin();
        let pi = agent(
            &[ANY_PROVIDER, "anthropic"],
            &[
                ("anthropic", "api.anthropic.com"),
                ("openai", "api.openai.com"),
                // A key injected for a host the Kit does not allow never gets here.
            ],
        );
        let agents = BTreeMap::from([
            ("claude".to_owned(), agent(&["anthropic"], &[])),
            ("pi".to_owned(), pi),
        ]);
        let found = detect(&table, &agents, &set(&["anthropic", "openai", "deepseek"]));
        for class in ModelClass::ALL {
            let by = |vendor: &str| {
                found
                    .ready
                    .iter()
                    .find(|r| r.class == Some(class) && r.vendor.as_deref() == Some(vendor))
                    .map(|r| (r.agent.as_str(), r.model.clone()))
            };
            assert_eq!(by("anthropic").map(|r| r.0), Some("claude"), "{class:?}");
            // openai has no agent of its own here: pi, with the qualified id.
            assert_eq!(
                by("openai"),
                table
                    .newest("openai", class)
                    .map(|model| ("pi", format!("openai/{model}"))),
                "{class:?}"
            );
            // deepseek: pi's Kit has neither its host nor its key.
            assert_eq!(by("deepseek"), None, "{class:?}");
        }
        let blocked = found
            .unreachable
            .iter()
            .map(|(r, reason)| (r.agent.as_str(), r.vendor.as_deref(), reason.as_str()))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            blocked.into_iter().collect::<Vec<_>>(),
            [(
                "pi",
                Some("deepseek"),
                "pi can't reach api.deepseek.com (its Kit must allow the host and inject the deepseek key for it)"
            )]
        );
        assert!(
            found
                .unreachable
                .iter()
                .all(|(r, _)| r.model.starts_with("deepseek/deepseek-"))
        );
        // The host alone is not enough: no injected key, no reach.
        let no_key = BTreeMap::from([("pi".to_owned(), agent(&[ANY_PROVIDER], &[]))]);
        let found = detect(&table, &no_key, &set(&["openai"]));
        assert_eq!(found.ready.len(), 0);
        assert_eq!(found.unreachable.len(), 3);
        // Without a stored key nothing is offered or blocked.
        let found = detect(&table, &agents, &BTreeSet::new());
        assert_eq!((found.ready.len(), found.unreachable.len()), (0, 0));
    }

    #[test]
    fn load_skips_a_multi_provider_agent_for_a_vendor_its_kit_cannot_reach() {
        let scope = tempfile::tempdir().unwrap();
        let directory = scope.path().join(DROPIN_DIR);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("marsh.yaml"),
            "enabled: true\nreviewers:\n  - {agent: pi, model: openai/gpt-6.1-terra}\n  - {agent: pi, model: deepseek/deepseek-v4-flash}\n  - {agent: pi, model: claude-sonnet-5-5}\n",
        )
        .unwrap();
        let facts = AgentFacts {
            prompt: true,
            model_option: true,
            multi_provider: true,
            reaches: BTreeMap::from([(
                "openai".to_owned(),
                BTreeSet::from(["api.openai.com".to_owned()]),
            )]),
        };
        let status = load(scope.path(), &BTreeMap::from([("pi".to_owned(), facts)]));
        assert_eq!(
            status
                .reviewers
                .iter()
                .map(|r| r.model.as_str())
                .collect::<Vec<_>>(),
            ["openai/gpt-6.1-terra"]
        );
        let mut reasons = status
            .skipped
            .iter()
            .map(|r| r.reason.clone().unwrap())
            .collect::<Vec<_>>();
        reasons.sort();
        assert_eq!(
            reasons,
            [
                "pi can't reach api.anthropic.com (its Kit must allow the host and inject the anthropic key for it)",
                "pi can't reach api.deepseek.com (its Kit must allow the host and inject the deepseek key for it)"
            ]
        );
    }

    /// The shape of what the `task` tool lists for each vendor's own agent, on
    /// any snapshot: a row per family, each family's newest model, small, mid,
    /// then large, newest first within a class, nicknames that resolve, every
    /// model eligible in the class its row says.
    fn assert_the_lists_have_their_shape(what: &str, table: &ClassTable) {
        let none = BTreeMap::new();
        for (agent, vendor, families) in FAMILIES {
            let at = format!("{what}: {agent}");
            let choices = agent_choices(table, agent, &[vendor.to_owned()], &none);
            let expected = expected_list(table, vendor, &families);
            assert!(!expected.is_empty(), "{at}: {expected:?}");
            // The same families, each listed with one of its tied newest
            // models, in class order and newest first within a class.
            let listed = |c: &ModelChoice| (c.class.clone(), released(table, &c.model));
            assert_eq!(
                choices.iter().map(listed).collect::<Vec<_>>(),
                expected
                    .iter()
                    .map(|e| (e.class.name().to_owned(), e.released.clone()))
                    .collect::<Vec<_>>(),
                "{at}: {choices:?} against {expected:?}"
            );
            let mut families = choices.iter().map(|c| c.family.clone()).collect::<Vec<_>>();
            families.sort();
            let mut wanted = expected
                .iter()
                .map(|e| e.family.clone())
                .collect::<Vec<_>>();
            wanted.sort();
            assert_eq!(families, wanted, "{at}");
            for choice in &choices {
                let one = expected.iter().find(|e| e.family == choice.family).unwrap();
                assert_eq!(choice.class, one.class.name(), "{at}: {choice:?}");
                assert!(
                    one.models.contains(&choice.model),
                    "{at}: {choice:?} is not one of {one:?}"
                );
            }
            assert_eq!(
                describe_choices(&BTreeMap::from([(agent.to_owned(), choices.clone())])),
                format!(
                    "{agent}: {}",
                    choices
                        .iter()
                        .map(|c| format!("{} ({}, {})", c.model, c.class, c.family))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "{at}"
            );
            for choice in &choices {
                let found = table.classify(&choice.model).unwrap();
                assert!(found.eligible, "{at}: {choice:?} {found:?}");
                assert_eq!(
                    found.class.map(ModelClass::name),
                    Some(choice.class.as_str())
                );
                assert_eq!(found.vendor.as_deref(), Some(vendor), "{at}: {choice:?}");
                // A nickname, in any case and with spaces, is the family's row;
                // the id itself is no nickname.
                let spelled = format!(" {} ", choice.family.to_ascii_uppercase());
                assert_eq!(
                    resolve_family(&choices, &spelled),
                    Ok(Some(choice.clone())),
                    "{at}"
                );
                assert_eq!(resolve_family(&choices, &choice.model), Ok(None), "{at}");
            }
            // A class with a row (every family of it may have aged out of the
            // list) starts with a model released as late as the vendor's
            // newest of that class. Two families released the same day may be
            // listed in either order, so the dates are compared, not the ids.
            for class in ModelClass::ALL {
                let Some(first) = choices.iter().find(|c| c.class == class.name()) else {
                    continue;
                };
                let Some(newest) = table.newest(vendor, class) else {
                    panic!("{at}: {class:?} is listed ({first:?}) but has no newest");
                };
                assert_eq!(
                    released(table, &first.model),
                    released(table, &newest),
                    "{at}: {class:?}: {first:?} against {newest}"
                );
            }
            assert_eq!(resolve_family(&choices, "mystery"), Ok(None));
        }
        assert_the_multi_provider_list_has_its_shape(what, table);
    }

    /// A multi-provider agent lists only the vendors its Kit reaches, with
    /// qualified ids, within the row cap; one nickname of two vendors is
    /// ambiguous.
    fn assert_the_multi_provider_list_has_its_shape(what: &str, table: &ClassTable) {
        let none = BTreeMap::new();
        let reaches = BTreeMap::from([("openai".to_owned(), vec!["api.openai.com".to_owned()])]);
        let pi = agent_choices(table, "pi", &[ANY_PROVIDER.to_owned()], &reaches);
        let codex = agent_choices(table, "codex", &["openai".to_owned()], &none);
        assert!(!pi.is_empty() && pi.len() <= CHOICE_ROWS, "{what}: {pi:?}");
        assert_eq!(
            pi.iter().map(|c| c.model.clone()).collect::<Vec<_>>(),
            codex
                .iter()
                .map(|c| format!("openai/{}", c.model))
                .collect::<Vec<_>>(),
            "{what}"
        );
        let unreached = agent_choices(table, "pi", &[ANY_PROVIDER.to_owned()], &none);
        assert_eq!(unreached.len(), 0);
        // Two vendors with one family name: the candidates, by id. Whichever
        // family of codex is listed will do (one may have aged out).
        let Some(listed) = codex.first().cloned() else {
            panic!("{what}: codex lists nothing");
        };
        let other = ModelChoice {
            model: format!("x/{}", listed.family),
            class: listed.class.clone(),
            family: listed.family.clone(),
        };
        let error = resolve_family(&[codex, vec![other]].concat(), &listed.family).unwrap_err();
        assert!(
            error.contains(&format!("{}, x/{}", listed.model, listed.family)),
            "{what}: {error}"
        );
    }

    #[test]
    fn an_agents_models_are_each_familys_newest_and_nicknames_resolve() {
        for (what, table) in refreshed_tables() {
            assert_the_lists_have_their_shape(&what, &table);
        }
        // A model added to the snapshot is the row, in release order (the
        // large families by release, not by name).
        for fixed in [&[][..], &A_REFRESH[..]] {
            let table = builtin_plus(fixed, &EVERY_FAMILY_NEWER);
            let list = |agent: &str, service: &str| {
                let choices = agent_choices(&table, agent, &[service.to_owned()], &BTreeMap::new());
                describe_choices(&BTreeMap::from([(agent.to_owned(), choices)]))
            };
            assert_eq!(
                list("codex", "openai"),
                "codex: gpt-x9-luna (small, luna), gpt-x9-terra (mid, terra), \
                 gpt-x9-sol (large, sol), gpt-x9-astra (large, astra)"
            );
            assert_eq!(
                list("claude", "anthropic"),
                "claude: claude-haiku-x9 (small, haiku), claude-sonnet-x9 (mid, sonnet), \
                 claude-opus-x9 (large, opus), claude-fable-x9 (large, fable)"
            );
        }
        assert_eq!(family_nickname("gpt-*luna*"), "luna");
        assert_eq!(family_nickname("claude-*-haiku*"), "haiku");
        assert_eq!(family_nickname("gpt-oss-20b*"), "oss");
        assert_eq!(family_nickname("mistral-large*"), "mistral-large");
        assert_eq!(family_nickname("haiku"), "haiku");
    }

    #[rustfmt::skip]
    const OWN_SNAPSHOT: [Row; 16] = [
        ("openai", "gpt-6-luna", "gpt-luna", "openai", 0.5, "2030-03-01"),
        ("openai", "gpt-7-luna", "gpt-luna", "openai", 0.5, "2030-06-01"),
        ("openai", "gpt-7-terra-2", "gpt-terra", "openai", 5.0, "2030-06-10"),
        ("openai", "gpt-7-terra", "gpt-terra", "openai", 5.0, "2030-06-10"),
        ("openai", "gpt-7-sol", "gpt-sol", "openai", 10.0, "2030-06-20"),
        ("openai", "gpt-7-astra", "gpt-astra", "openai", 50.0, "2030-06-05"),
        ("openai", "gpt-7-sol-preview", "gpt-sol", "openai", 10.0, "2030-07-01"),
        ("openai", "gpt-7-astra-20300801", "gpt-astra", "openai", 50.0, "2030-08-01"),
        ("openai", "gpt-5.9", "gpt-5", "openai", 10.0, "2030-08-01"),
        ("azure", "gpt-7-luna", "gpt-luna", "openai", 0.5, "2030-09-01"),
        ("anthropic", "claude-haiku-6-0", "claude-haiku", "anthropic", 0.5, "2029-01-01"),
        ("anthropic", "claude-sonnet-6-0", "claude-sonnet", "anthropic", 10.0, "2030-05-01"),
        ("anthropic", "claude-opus-6-0", "claude-opus", "anthropic", 20.0, "2030-06-01"),
        ("anthropic", "claude-fable-6-0", "claude-fable", "anthropic", 40.0, "2030-04-01"),
        ("anthropic", "claude-opus-4-9", "claude-opus", "anthropic", 25.0, "2030-09-01"),
        ("openrouter", "anthropic/claude-sonnet-9", "claude-sonnet", "anthropic", 10.0, "2030-09-01"),
    ];

    /// The same logic on a snapshot written out here, so nothing but the code
    /// decides the answer: the newest by release date, not by id; a shorter id
    /// on a tie; a family more than half a year behind left out; a retired,
    /// preview, dated, `-latest`, codex or re-hosted model never offered even
    /// when it is the newest.
    #[test]
    fn the_lists_follow_release_dates_on_a_snapshot_of_their_own() {
        let table = table_over(&rows(&OWN_SNAPSHOT));
        let list = |agent: &str, service: &str| {
            describe_choices(&BTreeMap::from([(
                agent.to_owned(),
                agent_choices(&table, agent, &[service.to_owned()], &BTreeMap::new()),
            )]))
        };
        assert_eq!(
            list("codex", "openai"),
            "codex: gpt-7-luna (small, luna), gpt-7-terra (mid, terra), \
             gpt-7-sol (large, sol), gpt-7-astra (large, astra)"
        );
        assert_eq!(
            list("claude", "anthropic"),
            "claude: claude-sonnet-6-0 (mid, sonnet), claude-opus-6-0 (large, opus), \
             claude-fable-6-0 (large, fable)"
        );
        for (vendor, class, model) in [
            ("openai", ModelClass::Small, Some("gpt-7-luna")),
            ("openai", ModelClass::Mid, Some("gpt-7-terra")),
            ("openai", ModelClass::Large, Some("gpt-7-sol")),
            // Newest by date even where its family is too old to be listed.
            ("anthropic", ModelClass::Small, Some("claude-haiku-6-0")),
            ("anthropic", ModelClass::Mid, Some("claude-sonnet-6-0")),
            ("anthropic", ModelClass::Large, Some("claude-opus-6-0")),
            ("google", ModelClass::Large, None),
        ] {
            assert_eq!(
                table.newest(vendor, class).as_deref(),
                model,
                "{vendor} {class:?}"
            );
        }
    }

    /// Release dates a given number of days behind 2030-12-10 as `day_number`
    /// counts them (365-day years of 31-day months, so 2030-06-16 is 180 days
    /// behind though the calendar says 177).
    #[rustfmt::skip]
    const LAGS: [Row; 7] = [
        ("openai", "gpt-b1-sol", "gpt-sol", "openai", 10.0, "2030-12-10"),
        ("openai", "gpt-b1-terra", "gpt-terra", "openai", 5.0, "2030-06-17"),
        ("openai", "gpt-b1-luna", "gpt-luna", "openai", 0.5, "2030-06-16"),
        ("openai", "gpt-b1-astra", "gpt-astra", "openai", 50.0, "2030-06-15"),
        ("anthropic", "claude-opus-b1", "claude-opus", "anthropic", 20.0, "2030-12-10"),
        ("anthropic", "claude-sonnet-b1", "claude-sonnet", "anthropic", 10.0, "2030-09-03"),
        ("anthropic", "claude-haiku-b1", "claude-haiku", "anthropic", 0.5, "2029-11-13"),
    ];

    /// A family is listed when it is at most 180 days behind the vendor's
    /// newest: 179 (terra) and 180 (luna) stay, 181 (astra) goes, as does one
    /// 400 days behind (haiku); one 100 days behind (sonnet) stays. Fails if
    /// the limit is anything but 180, or the distance is counted another way.
    #[test]
    fn a_family_is_listed_up_to_180_days_behind_the_vendors_newest() {
        let table = table_over(&rows(&LAGS));
        let list = |agent: &str, service: &str| {
            let choices = agent_choices(&table, agent, &[service.to_owned()], &BTreeMap::new());
            describe_choices(&BTreeMap::from([(agent.to_owned(), choices)]))
        };
        assert_eq!(
            list("codex", "openai"),
            "codex: gpt-b1-luna (small, luna), gpt-b1-terra (mid, terra), gpt-b1-sol (large, sol)"
        );
        assert_eq!(
            list("claude", "anthropic"),
            "claude: claude-sonnet-b1 (mid, sonnet), claude-opus-b1 (large, opus)"
        );
        // Too old to list is not too old to be the newest of its class.
        assert_eq!(
            table.newest("openai", ModelClass::Large).as_deref(),
            Some("gpt-b1-sol")
        );
        assert_eq!(
            table.newest("anthropic", ModelClass::Small).as_deref(),
            Some("claude-haiku-b1")
        );
    }

    /// Eleven families of three vendors, each newer than the last by a day.
    #[rustfmt::skip]
    const ELEVEN: [Row; 11] = [
        ("openai", "gpt-t1-luna", "gpt-luna", "openai", 0.5, "2030-03-01"),
        ("openai", "gpt-t1-terra", "gpt-terra", "openai", 5.0, "2030-03-02"),
        ("openai", "gpt-t1-sol", "gpt-sol", "openai", 10.0, "2030-03-03"),
        ("openai", "gpt-t1-astra", "gpt-astra", "openai", 50.0, "2030-03-04"),
        ("anthropic", "claude-haiku-t1", "claude-haiku", "anthropic", 0.5, "2030-03-05"),
        ("anthropic", "claude-sonnet-t1", "claude-sonnet", "anthropic", 10.0, "2030-03-06"),
        ("anthropic", "claude-fable-t1", "claude-fable", "anthropic", 40.0, "2030-03-07"),
        ("anthropic", "claude-opus-t1", "claude-opus", "anthropic", 20.0, "2030-03-08"),
        ("google", "gemma-t1", "gemma", "google", 0.1, "2030-03-09"),
        ("google", "gemini-t1-flash", "gemini-flash", "google", 0.5, "2030-03-10"),
        ("google", "gemini-t1-pro", "gemini-pro", "google", 10.0, "2030-03-11"),
    ];

    /// A multi-provider agent that reaches three vendors is offered the eight
    /// newest of their eleven families (the three oldest, gpt-t1-luna, terra
    /// and sol, are cut), ordered small, mid, large, then by vendor, then
    /// newest first. Fails if the cap is not 8 or the cut keeps the oldest.
    #[test]
    fn a_multi_provider_agent_is_offered_the_eight_newest_families() {
        let table = table_over(&rows(&ELEVEN));
        let reaches = BTreeMap::from([
            ("anthropic".to_owned(), vec!["api.anthropic.com".to_owned()]),
            ("openai".to_owned(), vec!["api.openai.com".to_owned()]),
            (
                "google".to_owned(),
                vec!["generativelanguage.googleapis.com".to_owned()],
            ),
        ]);
        let pi = agent_choices(&table, "pi", &[ANY_PROVIDER.to_owned()], &reaches);
        assert_eq!(
            describe_choices(&BTreeMap::from([("pi".to_owned(), pi)])),
            "pi: anthropic/claude-haiku-t1 (small, haiku), google/gemini-t1-flash (small, flash), \
             google/gemma-t1 (small, gemma), anthropic/claude-sonnet-t1 (mid, sonnet), \
             google/gemini-t1-pro (mid, pro), anthropic/claude-opus-t1 (large, opus), \
             anthropic/claude-fable-t1 (large, fable), openai/gpt-t1-astra (large, astra)"
        );
    }

    #[test]
    fn a_fixture_agent_advertising_retired_models_gets_only_the_curated_newest() {
        let scope = tempfile::tempdir().unwrap();
        let directory = scope.path().join(DROPIN_DIR);
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("narwhal.yaml"),
            "enabled: true\nreviewers:\n\
             - {agent: pi, model: openai/o3-pro}\n\
             - {agent: pi, model: openai/o3-pro, class: large, vendor: openai}\n\
             - {agent: codex, model: gpt-4o}\n\
             - {agent: codex, model: gpt-4.1-mini, class: small, vendor: openai}\n\
             - {agent: claude, model: claude-3-opus}\n\
             - {agent: claude, model: claude-3-opus-20240229, class: large, vendor: anthropic}\n\
             - {agent: pi, model: x-ai/grok-4.7, class: mid, vendor: xai}\n\
             - {agent: claude, model: claude-haiku-5-5}\n\
             - {agent: claude, model: claude-sonnet-5-5}\n\
             - {agent: claude, model: claude-opus-5-5}\n\
             - {agent: codex, model: gpt-6-luna}\n\
             - {agent: codex, model: gpt-6.1-terra}\n\
             - {agent: codex, model: gpt-6.1-sol}\n\
             - {agent: codex, model: gpt-4o, allow_uncurated: true}\n",
        )
        .unwrap();
        let pi = AgentFacts {
            prompt: true,
            model_option: true,
            multi_provider: true,
            reaches: BTreeMap::from([(
                "openai".to_owned(),
                BTreeSet::from(["api.openai.com".to_owned()]),
            )]),
        };
        let mut known = agents(&[("claude", true), ("codex", true)]);
        known.insert("pi".into(), pi);
        let status = load(scope.path(), &known);
        assert_eq!(status.errors, Vec::<String>::new());
        let ready = status
            .reviewers
            .iter()
            .map(|r| r.model.as_str())
            .collect::<Vec<_>>();
        // The explicit opt-in (last line) is the only way a retired model gets in.
        assert_eq!(
            ready,
            [
                "claude-haiku-5-5",
                "gpt-6-luna",
                "claude-sonnet-5-5",
                "gpt-4o",
                "gpt-6.1-terra",
                "claude-opus-5-5",
                "gpt-6.1-sol",
            ]
        );
        let skipped = status
            .skipped
            .iter()
            .map(|r| (r.model.as_str(), r.reason.clone().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(skipped.len(), 7, "{skipped:?}");
        for (model, reason) in &skipped {
            let retired = !model.contains("grok");
            assert_eq!(reason.contains("is retired"), retired, "{model}: {reason}");
            assert!(reason.contains("allow_uncurated"), "{reason}");
            assert!(reason.starts_with(*model), "{reason}");
        }
        // No peer-review context row names a retired model.
        let text = context(&status, &["claude".into(), "codex".into(), "pi".into()]);
        for old in ["o3-pro", "claude-3", "gpt-4.1"] {
            assert!(!text.contains(old), "{text}");
        }
    }

    /// Every model detection, the `task` tool's lists and `newest` offer.
    fn offered(table: &ClassTable) -> Vec<String> {
        let reaches = VENDOR_HOSTS
            .iter()
            .map(|(vendor, host)| ((*vendor).to_owned(), vec![(*host).to_owned()]))
            .collect::<BTreeMap<_, _>>();
        let mut offered = agent_choices(table, "pi", &[ANY_PROVIDER.to_owned()], &reaches)
            .into_iter()
            .map(|choice| choice.model)
            .collect::<Vec<_>>();
        for (name, service) in [("codex", "openai"), ("claude", "anthropic")] {
            offered.extend(
                agent_choices(table, name, &[service.to_owned()], &BTreeMap::new())
                    .into_iter()
                    .map(|choice| choice.model),
            );
        }
        for (vendor, _) in VENDOR_HOSTS {
            for class in ModelClass::ALL {
                offered.extend(table.newest(vendor, class));
            }
        }
        offered
    }

    /// What detection picks for an agent that has only Anthropic's key.
    fn detected(table: &ClassTable) -> Vec<String> {
        let claude = BTreeMap::from([("claude".to_owned(), agent(&["anthropic"], &[]))]);
        detect(table, &claude, &set(&["anthropic"]))
            .ready
            .into_iter()
            .map(|r| r.model)
            .collect()
    }

    #[test]
    fn detection_and_the_task_tools_model_lists_never_reach_for_retired_models() {
        let retired = [
            "o3-pro", "o3", "o1", "o4-mini", "gpt-4", "gpt-4o", "gpt-4.1", "gpt-5",
        ];
        let never = NEWER_BUT_NEVER_OFFERED.map(|(_, id, ..)| id);
        let current = refreshed_tables().into_iter().chain([
            (
                "models newer than all that are never offered".to_owned(),
                builtin_plus(&[], &NEWER_BUT_NEVER_OFFERED),
            ),
            (
                "the same after a refresh".to_owned(),
                builtin_plus(&A_REFRESH, &NEWER_BUT_NEVER_OFFERED),
            ),
        ]);
        for (what, table) in current {
            let offered = offered(&table);
            assert!(offered.len() > 8, "{what}: {offered:?}");
            for model in &offered {
                let found = table.classify(model).unwrap();
                assert!(found.eligible, "{what}: {model}: {found:?}");
                assert_ne!(found.how, RETIRED, "{what}: {model}");
                assert!(
                    !retired.contains(&normalize(model).as_str()),
                    "{what}: {model}"
                );
                assert!(
                    !never.contains(&normalize(model).as_str()),
                    "{what}: {model}"
                );
                assert!(
                    !never.iter().any(|id| model.ends_with(id)),
                    "{what}: {model}"
                );
            }
            // Small, mid, large: each class's newest, whatever the snapshot is.
            let newest = |class| table.newest("anthropic", class).unwrap();
            assert_eq!(
                detected(&table),
                [
                    newest(ModelClass::Small),
                    newest(ModelClass::Mid),
                    newest(ModelClass::Large)
                ],
                "{what}"
            );
        }
        // Offering the newest never needs the retired models: the same lists
        // as without them, though they are the newest of all.
        for fixed in [&[][..], &A_REFRESH[..]] {
            let with = builtin_plus(fixed, &NEWER_BUT_NEVER_OFFERED);
            let without = builtin_plus(fixed, &[]);
            assert_eq!(offered(&with), offered(&without));
            assert_eq!(detected(&with), detected(&without));
        }
        // And every model of the compiled-in snapshot a retired glob names
        // is refused, whatever its date.
        for model in ["claude-opus-4-8", "claude-sonnet-4-6", "gpt-5.5"] {
            let found = ClassTable::builtin().classify(model).unwrap();
            assert!(
                !found.eligible && found.how == RETIRED,
                "{model}: {found:?}"
            );
        }
    }

    #[test]
    fn globs() {
        assert!(glob("claude-sonnet-*", "claude-sonnet-5-5"));
        assert!(glob("gpt-*sol*", "gpt-sol"));
        assert!(glob("gemini-*flash*", "gemini-3.8-flash"));
        assert!(!glob("gemini-*flash*", "gemini-3.1-pro"));
        assert!(glob("sonnet", "sonnet"));
        assert!(!glob("sonnet", "sonnet-4"));
        assert!(!glob("a*a", "a"));
    }
}
