//! The user's terminal, as seen from the shell VM and its jobs: which
//! identity variables cross from the Mac, and which links a job may ask the
//! Mac to open (`docs/agents.md`, `docs/security.md`).

use std::collections::BTreeMap;

/// Variables copied from the Mac's environment into an interactive session
/// (and from there to its jobs). Each names the terminal, never the user.
pub const IDENTITY_VARIABLES: [&str; 9] = [
    "TERM",
    "COLORTERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "LC_TERMINAL",
    "LC_TERMINAL_VERSION",
    "ITERM_SESSION_ID",
    "KITTY_WINDOW_ID",
    "WEZTERM_PANE",
];

/// `TERM` values passed through as they are; the shell and Kit images ship
/// terminfo for each. Any other value becomes `xterm-256color`.
const PORTABLE_TERMS: [&str; 12] = [
    "xterm",
    "xterm-256color",
    "xterm-color",
    "screen",
    "screen-256color",
    "tmux",
    "tmux-256color",
    "vt100",
    "vt220",
    "linux",
    "ansi",
    "dumb",
];

const MAX_IDENTITY_VALUE: usize = 128;

/// The terminal identity in `variables`, filtered to [`IDENTITY_VARIABLES`]
/// with short, plain values. A `TERM` the Linux side may not know (such as
/// `xterm-ghostty` or `xterm-kitty`) becomes `xterm-256color`.
#[must_use]
pub fn identity<N, V>(variables: impl IntoIterator<Item = (N, V)>) -> BTreeMap<String, String>
where
    N: AsRef<str>,
    V: AsRef<str>,
{
    let mut identity = BTreeMap::new();
    for (name, value) in variables {
        let (name, value) = (name.as_ref(), value.as_ref());
        if !IDENTITY_VARIABLES.contains(&name) || !plain_value(value) {
            continue;
        }
        let value = if name == "TERM" && !PORTABLE_TERMS.contains(&value) {
            "xterm-256color"
        } else {
            value
        };
        identity.insert(name.to_owned(), value.to_owned());
    }
    identity
}

fn plain_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_VALUE
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+' | b'@')
        })
}

/// Whether `character` could act on a terminal or hide text in a line:
/// C0 and C1 controls (ESC, CSI, OSC, BEL, CR, DEL...), the Unicode line and
/// paragraph separators, and the bidirectional overrides and isolates.
#[must_use]
pub fn is_terminal_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// `text` for one line on the user's terminal: every character
/// [`is_terminal_unsafe`] becomes `?`. The one filter for every string a
/// workload, a Kit or a remote run chose that the Mac prints (receipt and job
/// fields, daemon error text).
#[must_use]
pub fn display_safe(text: &str) -> String {
    text.chars()
        .map(|c| if is_terminal_unsafe(c) { '?' } else { c })
        .collect()
}

/// Like [`display_safe`] for text of several lines: newlines and tabs stay.
#[must_use]
pub fn display_safe_text(text: &str) -> String {
    text.chars()
        .map(|c| {
            if is_terminal_unsafe(c) && !matches!(c, '\n' | '\t') {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// [`display_safe_text`] for bytes that arrive in chunks, such as a patch a
/// cloud run produced and the Mac shows on a terminal. A character that a
/// chunk boundary splits is held back for the next call.
#[derive(Debug, Default)]
pub struct DisplayFilter {
    held: Vec<u8>,
}

impl DisplayFilter {
    /// The safe text for the bytes so far, without a split character's tail.
    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.held.extend_from_slice(chunk);
        let end = match std::str::from_utf8(&self.held) {
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            _ => self.held.len(),
        };
        let text = display_safe_text(&String::from_utf8_lossy(&self.held[..end]));
        self.held.drain(..end);
        text
    }

    /// What is left at the end of the stream.
    pub fn finish(&mut self) -> String {
        let text = display_safe_text(&String::from_utf8_lossy(&self.held));
        self.held.clear();
        text
    }
}

/// The longest link a job may hand to the Mac.
pub const MAX_URL_BYTES: usize = 4096;

/// Why a link cannot be opened on the Mac, or `None` for an `http://` or
/// `https://` URL with a host, at most [`MAX_URL_BYTES`] of printable ASCII.
#[must_use]
pub fn url_refusal(url: &str) -> Option<&'static str> {
    let lower = url.get(..8).unwrap_or(url).to_ascii_lowercase();
    let rest = if lower.starts_with("https://") {
        &url[8..]
    } else if lower.starts_with("http://") {
        &url[7..]
    } else {
        return Some("only http and https links can be opened");
    };
    if url.len() > MAX_URL_BYTES {
        return Some("the link is too long");
    }
    if !url.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Some("the link contains spaces or characters that are not plain ASCII");
    }
    if rest.is_empty() || matches!(rest.as_bytes()[0], b'/' | b'?' | b'#') {
        return Some("the link has no host");
    }
    None
}

/// `scheme://host` of a link [`url_refusal`] accepted: what a receipt keeps.
#[must_use]
pub fn url_origin(url: &str) -> String {
    let start = url.find("://").map_or(0, |index| index + 3);
    let end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |index| start + index);
    let authority = &url[start..end];
    // Never keep a `user:password@` part.
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{}{host}", &url[..start]).to_ascii_lowercase()
}

/// `url` as an OSC 8 hyperlink labelled with itself (an accepted link has no
/// control bytes, so it cannot end the sequence early).
#[must_use]
pub fn hyperlink(url: &str) -> String {
    format!("\x1b]8;;{url}\x1b\\{url}\x1b]8;;\x1b\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_filter_holds_a_split_character_and_hides_controls() {
        let bytes = "é\u{1b}[2Jü\u{9b}x".as_bytes();
        for split in 0..=bytes.len() {
            let mut filter = DisplayFilter::default();
            let mut shown = filter.push(&bytes[..split]);
            shown += &filter.push(&bytes[split..]);
            shown += &filter.finish();
            assert_eq!(shown, "é?[2Jü?x", "split at {split}");
        }
        assert_eq!(DisplayFilter::default().push(&[0xff, b'a']), "\u{fffd}a");
    }

    #[test]
    fn display_safe_removes_everything_a_terminal_could_act_on() {
        let hostile =
            "a\u{1b}]52;c;AAAA\u{7}b\u{1b}[2Jc\u{9b}31md\rE\u{7f}f\u{202e}g\u{2066}h\u{85}i\nj\tk";
        let shown = display_safe(hostile);
        assert!(!shown.chars().any(is_terminal_unsafe), "{shown:?}");
        assert_eq!(shown, "a?]52;c;AAAA?b?[2Jc?31md?E?f?g?h?i?j?k");
        assert_eq!(display_safe("plain ünïcode / text"), "plain ünïcode / text");
        let text = display_safe_text(hostile);
        assert_eq!(text, "a?]52;c;AAAA?b?[2Jc?31md?E?f?g?h?i\nj\tk");
    }

    #[test]
    fn identity_keeps_only_listed_plain_terminal_variables() {
        let identity = identity([
            ("TERM", "xterm-ghostty"),
            ("TERM_PROGRAM", "ghostty"),
            ("TERM_PROGRAM_VERSION", "1.2.3"),
            ("COLORTERM", "truecolor"),
            ("ITERM_SESSION_ID", "w0t0p0:6F3E5A0B-1C2D"),
            (
                "GHOSTTY_RESOURCES_DIR",
                "/Applications/Ghostty.app/Contents",
            ),
            ("TMUX", "/private/tmp/tmux-501/default,1,0"),
            ("OPENAI_API_KEY", "sk-not-a-key"),
            ("LC_TERMINAL", "iTerm2\u{1b}]0;x"),
            ("WEZTERM_PANE", "a b"),
            ("KITTY_WINDOW_ID", &"1".repeat(200)),
            ("LC_TERMINAL_VERSION", ""),
        ]);
        assert_eq!(
            identity,
            BTreeMap::from([
                ("COLORTERM".into(), "truecolor".into()),
                ("ITERM_SESSION_ID".into(), "w0t0p0:6F3E5A0B-1C2D".into()),
                ("TERM".into(), "xterm-256color".into()),
                ("TERM_PROGRAM".into(), "ghostty".into()),
                ("TERM_PROGRAM_VERSION".into(), "1.2.3".into()),
            ])
        );
    }

    #[test]
    fn portable_terms_pass_and_tmux_stays_tmux() {
        for term in ["xterm", "xterm-256color", "tmux-256color", "screen", "dumb"] {
            assert_eq!(identity([("TERM", term)])["TERM"], term);
        }
        for term in ["xterm-kitty", "wezterm", "alacritty", "foot"] {
            assert_eq!(identity([("TERM", term)])["TERM"], "xterm-256color");
        }
    }

    #[test]
    fn only_web_links_with_a_host_are_opened() {
        for url in [
            "https://example.com",
            "http://localhost:8080/callback?code=1&state=2",
            "HTTPS://Example.com/a#b",
        ] {
            assert_eq!(url_refusal(url), None, "{url}");
        }
        for url in [
            "file:///etc/passwd",
            "/tmp/report.html",
            "vscode://file/x",
            "javascript:alert(1)",
            "https://",
            "https:///path",
            "https://exa mple.com",
            "https://example.com/\u{1b}]8;;",
            "https://example.com/caf\u{e9}",
            "-a Calculator",
            "",
        ] {
            assert!(url_refusal(url).is_some(), "{url}");
        }
        assert!(url_refusal(&format!("https://e.com/{}", "a".repeat(MAX_URL_BYTES))).is_some());
    }

    #[test]
    fn origins_drop_path_query_and_credentials() {
        assert_eq!(
            url_origin("https://user:pw@Example.com:8443/a?token=x#y"),
            "https://example.com:8443"
        );
        assert_eq!(url_origin("http://localhost?x"), "http://localhost");
    }
}
