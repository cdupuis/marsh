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

/// Whether `character` could act on a terminal or hide or reorder text in a
/// line: C0 and C1 controls (ESC, CSI, OSC, BEL, CR, DEL...), the Unicode line
/// and paragraph separators, the bidirectional embeddings, overrides and
/// isolates (LRE RLE PDF LRO RLO, LRI RLI FSI PDI), and characters that
/// render as nothing, so text can hide in them or ride on them: zero-width
/// space, BOM, word joiner and invisible operators, soft hyphen, the combining
/// grapheme joiner, Hangul and Braille fillers, Mongolian separators, the
/// deprecated format characters, interlinear annotation and object
/// replacement, the variation selectors, and the tag block that smuggles
/// ASCII. The marks LRM, RLM and ALM stay, since right-to-left text uses them.
/// The zero-width joiners and the emoji variation selectors (U+FE0E, U+FE0F)
/// are decided in context by [`display_safe`].
#[must_use]
pub fn is_terminal_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{0600}'..='\u{0605}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{08e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0d}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffc}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e01ef}'
        )
}

fn is_joiner(character: char) -> bool {
    matches!(character, '\u{200c}' | '\u{200d}')
}

fn is_emoji_selector(character: char) -> bool {
    matches!(character, '\u{fe0e}' | '\u{fe0f}')
}

/// A character that can be an emoji or part of an emoji sequence: the symbol
/// blocks and the pictograph planes, skin tones, and the emoji selector.
fn emojiish(character: char) -> bool {
    matches!(
        character,
        '\u{00a9}'
            | '\u{00ae}'
            | '\u{203c}'
            | '\u{2049}'
            | '\u{2122}'
            | '\u{2139}'
            | '\u{2194}'..='\u{21aa}'
            | '\u{231a}'..='\u{23ff}'
            | '\u{24c2}'
            | '\u{25aa}'..='\u{25fe}'
            | '\u{2600}'..='\u{27bf}'
            | '\u{2934}'..='\u{2935}'
            | '\u{2b05}'..='\u{2b55}'
            | '\u{3030}'
            | '\u{303d}'
            | '\u{3297}'
            | '\u{3299}'
            | '\u{1f000}'..='\u{1faff}'
            | '\u{fe0f}'
    )
}

/// Scripts that need the joiners: Arabic and Persian, the Indic scripts,
/// Myanmar and Khmer.
fn joining_script(character: char) -> bool {
    matches!(
        character,
        '\u{0620}'..='\u{06ff}'
            | '\u{0750}'..='\u{077f}'
            | '\u{08a0}'..='\u{08ff}'
            | '\u{0900}'..='\u{0dff}'
            | '\u{1000}'..='\u{109f}'
            | '\u{1780}'..='\u{17ff}'
            | '\u{fb50}'..='\u{fdff}'
            | '\u{fe70}'..='\u{fefc}'
    )
}

/// A zero-width joiner stays only inside an emoji sequence (both neighbours
/// emoji); a non-joiner or joiner also between two letters of a script that
/// needs them. Anywhere else, including next to a removed character, it only
/// hides, and it is replaced.
fn joins(joiner: char, before: Option<char>, after: Option<char>) -> bool {
    let (Some(before), Some(after)) = (before, after) else {
        return false;
    };
    (joiner == '\u{200d}' && emojiish(before) && emojiish(after))
        || (joining_script(before) && joining_script(after))
}

/// An emoji selector stays only after an emoji (or a keycap base followed by
/// the combining keycap): elsewhere it carries a bit and shows nothing.
fn selects(before: Option<char>, after: Option<char>) -> bool {
    before.is_some_and(|c| emojiish(c) && c != '\u{fe0f}')
        || (before.is_some_and(|c| matches!(c, '0'..='9' | '#' | '*')) && after == Some('\u{20e3}'))
}

fn sanitize(text: &str, keep_lines: bool, before: Option<char>, after: Option<char>) -> String {
    let characters = text.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(text.len());
    let mut previous = before;
    for (index, &c) in characters.iter().enumerate() {
        let next = characters.get(index + 1).copied().or(after);
        let kept = if is_joiner(c) {
            joins(c, previous, next)
        } else if is_emoji_selector(c) {
            selects(previous, next)
        } else {
            !is_terminal_unsafe(c) || (keep_lines && matches!(c, '\n' | '\t'))
        };
        let shown = if kept { c } else { '?' };
        out.push(shown);
        previous = Some(shown);
    }
    out
}

/// `text` for one line on the user's terminal: every character
/// [`is_terminal_unsafe`] (and a joiner that joins nothing) becomes `?`. The
/// one filter for every string a workload, a Kit or a remote run chose that the
/// Mac prints (receipt and job fields, daemon error text).
#[must_use]
pub fn display_safe(text: &str) -> String {
    sanitize(text, false, None, None)
}

/// Like [`display_safe`] for text of several lines: newlines and tabs stay.
#[must_use]
pub fn display_safe_text(text: &str) -> String {
    sanitize(text, true, None, None)
}

/// [`display_safe_text`] for bytes that arrive in chunks, such as a patch a
/// cloud run produced and the Mac shows on a terminal. A character that a
/// chunk boundary splits, and a joiner at the end of a chunk, wait for the
/// next call.
#[derive(Debug, Default)]
pub struct DisplayFilter {
    held: Vec<u8>,
    last: Option<char>,
}

impl DisplayFilter {
    /// The safe text for the bytes so far, without a split character's tail.
    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.held.extend_from_slice(chunk);
        let mut end = match std::str::from_utf8(&self.held) {
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            _ => self.held.len(),
        };
        let mut text = String::from_utf8_lossy(&self.held[..end]);
        while let Some(joiner) = text.chars().next_back().filter(|c| is_joiner(*c)) {
            end -= joiner.len_utf8();
            text = String::from_utf8_lossy(&self.held[..end]);
        }
        let shown = sanitize(&text, true, self.last, None);
        self.last = shown.chars().next_back().or(self.last);
        self.held.drain(..end);
        shown
    }

    /// What is left at the end of the stream.
    pub fn finish(&mut self) -> String {
        let shown = sanitize(&String::from_utf8_lossy(&self.held), true, self.last, None);
        self.held.clear();
        shown
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
    fn display_safe_hides_nothing_and_keeps_real_text() {
        // Characters that vanish, reorder, or smuggle ASCII.
        for hidden in [
            "a\u{200b}b",
            "a\u{feff}b",
            "a\u{2060}b",
            "a\u{2064}b",
            "a\u{e0041}b",
            "a\u{202a}b",
            "a\u{202b}b",
            "a\u{202c}b",
            "a\u{202d}b",
            "a\u{202e}b",
            "a\u{2066}b",
            "a\u{2067}b",
            "a\u{2068}b",
            "a\u{2069}b",
            // A joiner that joins nothing, or joins ASCII, hides.
            "a\u{200d}b",
            "a\u{200c}b",
            "\u{200d}",
            "👨\u{200d}",
        ] {
            let shown = display_safe(hidden);
            assert!(shown.contains('?'), "{hidden:?} -> {shown:?}");
            assert!(
                !shown.chars().any(|c| is_terminal_unsafe(c) || is_joiner(c)),
                "{shown:?}"
            );
        }
        // Real text, including right-to-left marks and joined emoji.
        for kept in [
            "日本語のテキスト 한국어 中文",
            "👨\u{200d}👩\u{200d}👧 family, 🏳\u{fe0f}\u{200d}🌈",
            "שלום\u{200f} עולם\u{200e} \u{061c}مرحبا",
            "می\u{200c}خواهم",
            "e\u{301} combining, ünïcode",
            "❤\u{fe0f} ☺\u{fe0e} 1\u{fe0f}\u{20e3} 👍🏽 🇯🇵",
        ] {
            assert_eq!(display_safe(kept), kept);
        }
    }

    #[test]
    fn display_filter_keeps_a_joined_emoji_across_any_split() {
        let text = "x 👨\u{200d}👩\u{200d}👧 y \u{200d}z";
        let bytes = text.as_bytes();
        for split in 0..=bytes.len() {
            let mut filter = DisplayFilter::default();
            let mut shown = filter.push(&bytes[..split]);
            shown += &filter.push(&bytes[split..]);
            shown += &filter.finish();
            assert_eq!(shown, "x 👨\u{200d}👩\u{200d}👧 y ?z", "split at {split}");
        }
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
