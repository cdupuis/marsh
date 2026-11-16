//! `marsh services status --json`'s `containers` and `ports` (E2, the shape
//! agreed with Narwhal's N3): display only, built from the base workspace's own
//! containers as the services agent lists them through the same filter as a job.
//!
//! ```json
//! "containers": [{"name": "app-db-1", "service": "db", "state": "running", "health": "healthy"}],
//! "ports": [{"service": "db", "container_port": 5432, "host_port": 5432, "protocol": "tcp"}]
//! ```
//!
//! Everything in the engine's answer is untrusted text: names, states and
//! health are reduced to plain bounded words, and nothing here names a VM,
//! volume, snapshot, engine or sbx.

use marsh_sbx::services_relay::{AttemptScope, Relay};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    sync::mpsc,
    thread,
    time::Duration,
};

const MAX_CONTAINERS: usize = 256;
const MAX_TAG_EVENTS: usize = 64;
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_NAME: usize = 128;
const DEADLINE: Duration = Duration::from_secs(3);

/// What the status shows of the base workspace's engine.
#[derive(Clone, Debug, Default)]
pub(crate) struct View {
    pub containers: Vec<Value>,
    pub ports: Vec<Value>,
    /// Image tags a `BuildKit` build changed that it may not (display only).
    pub tag_events: Vec<Value>,
}

/// The base workspace's containers, published ports and image tag events, or why
/// the containers could not be read. The events are the agent's own answer on
/// the same filtered endpoint; an agent that does not know the route refuses
/// it, and that, like any failure to read them, is no events.
pub(crate) fn read(channel: &dyn Channel) -> Result<View, String> {
    let (containers, ports) = parse(&get(channel, "/containers/json?all=1")?)?;
    let tag_events = get(channel, TAG_EVENTS_PATH)
        .map(|body| parse_tag_events(&body))
        .unwrap_or_default();
    Ok(View {
        containers,
        ports,
        tag_events,
    })
}

const TAG_EVENTS_PATH: &str = "/_marsh/tag-events";

/// A byte stream.
pub(crate) trait Duplex: Read + Write + Send {}
impl<T: Read + Write + Send> Duplex for T {}

/// A stream and what closes it again.
pub(crate) type Opened = (Box<dyn Duplex>, Box<dyn FnOnce() + Send>);

/// A way to open the daemon's own status channel to the base workspace's
/// filtered docker endpoint, and what closes it again.
pub(crate) trait Channel {
    fn open(&self) -> Result<Opened, String>;
}

impl Channel for Relay {
    fn open(&self) -> Result<Opened, String> {
        let authority =
            AttemptScope::status(self.project_path()).map_err(|error| error.to_string())?;
        let stream = self
            .open_docker(&authority)
            .map_err(|error| error.to_string())?;
        let closer = stream.clone();
        Ok((Box::new(stream), Box::new(move || closer.close())))
    }
}

/// One `GET` on a status channel, read only, bounded in time.
fn get(channel: &dyn Channel, path: &str) -> Result<Vec<u8>, String> {
    let (mut stream, close) = channel.open()?;
    let (send, receive) = mpsc::sync_channel(1);
    let path = path.to_owned();
    thread::spawn(move || {
        let _ = send.send(exchange(&mut stream, &path));
    });
    let body = match receive.recv_timeout(DEADLINE) {
        Ok(outcome) => outcome,
        Err(_) => Err("the services engine did not answer in time".to_owned()),
    };
    close();
    body
}

/// Send one `GET` and read the whole answer.
fn exchange(stream: &mut (impl Read + Write), path: &str) -> Result<Vec<u8>, String> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: marsh-status\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    response(stream)
}

/// One HTTP/1.1 response: the status, then a `Content-Length` or chunked body.
fn response(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let header_end = loop {
        if let Some(at) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        if data.len() > 32 * 1024 {
            return Err("the services engine's answer has an oversized header".into());
        }
        let count = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("the services engine closed before it answered".into());
        }
        data.extend_from_slice(&buffer[..count]);
    };
    let head = String::from_utf8_lossy(&data[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status.split(' ').nth(1) != Some("200") {
        return Err(format!("the services engine answered {}", bounded(status)));
    }
    let (mut length, mut chunked) = (None, false);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse::<usize>().ok(),
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }
    let mut rest = data[header_end + 4..].to_vec();
    let mut read_more = |rest: &mut Vec<u8>, stream: &mut dyn Read| -> Result<bool, String> {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        rest.extend_from_slice(&buffer[..count]);
        Ok(count > 0)
    };
    if chunked {
        let mut body = Vec::new();
        loop {
            let line_end = loop {
                if let Some(at) = rest.windows(2).position(|window| window == b"\r\n") {
                    break at;
                }
                if !read_more(&mut rest, stream)? {
                    return Err("a truncated chunked answer".into());
                }
            };
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&rest[..line_end])
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim(),
                16,
            )
            .map_err(|_| "an invalid chunk size".to_owned())?;
            rest.drain(..line_end + 2);
            if size == 0 {
                return Ok(body);
            }
            if body.len() + size > MAX_BODY {
                return Err("the services engine's answer is too large".into());
            }
            while rest.len() < size + 2 {
                if !read_more(&mut rest, stream)? {
                    return Err("a truncated chunk".into());
                }
            }
            body.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
        }
    }
    match length {
        Some(length) if length <= MAX_BODY => {
            while rest.len() < length {
                if !read_more(&mut rest, stream)? {
                    return Err("a truncated answer".into());
                }
            }
            rest.truncate(length);
            Ok(rest)
        }
        Some(_) => Err("the services engine's answer is too large".into()),
        None => {
            while rest.len() <= MAX_BODY && read_more(&mut rest, stream)? {}
            Ok(rest)
        }
    }
}

fn bounded(text: &str) -> String {
    plain(text, 64)
}

/// Plain text, one line, bounded: control characters and anything but
/// printable ASCII and ordinary letters are dropped.
fn plain(text: &str, limit: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control() && *c != '\u{202e}')
        .take(limit)
        .collect()
}

fn word(text: &str) -> String {
    let word: String = text
        .chars()
        .take(16)
        .filter(char::is_ascii_lowercase)
        .collect();
    if word.is_empty() {
        "unknown".into()
    } else {
        word
    }
}

fn parse(body: &[u8]) -> Result<(Vec<Value>, Vec<Value>), String> {
    let listed: Vec<Value> = serde_json::from_slice(body)
        .map_err(|_| "the services engine's list is not readable".to_owned())?;
    let mut containers = Vec::new();
    let mut ports = BTreeSet::new();
    for entry in listed.iter().take(MAX_CONTAINERS) {
        let name = entry
            .get("Names")
            .and_then(Value::as_array)
            .and_then(|names| names.first())
            .and_then(Value::as_str)
            .map(|name| plain(name.trim_start_matches('/'), MAX_NAME))
            .filter(|name| !name.is_empty());
        let Some(name) = name else { continue };
        let service = entry
            .get("Labels")
            .and_then(|labels| labels.get("com.docker.compose.service"))
            .and_then(Value::as_str)
            .map(|service| plain(service, MAX_NAME))
            .filter(|service| !service.is_empty())
            .unwrap_or_else(|| name.clone());
        let status = entry
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let health = if status.contains("(healthy)") {
            json!("healthy")
        } else if status.contains("(unhealthy)") {
            json!("unhealthy")
        } else if status.contains("(health: starting)") {
            json!("starting")
        } else {
            Value::Null
        };
        let state = word(
            entry
                .get("State")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        for port in entry
            .get("Ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // Only 127.0.0.1 is forwarded into jobs; a binding on another loopback
            // address (127.0.0.2, ::1) is not published to them.
            if port
                .get("IP")
                .and_then(Value::as_str)
                .is_some_and(|ip| ip != "127.0.0.1")
            {
                continue;
            }
            let (Some(container), Some(host)) = (
                port.get("PrivatePort").and_then(Value::as_u64),
                port.get("PublicPort").and_then(Value::as_u64),
            ) else {
                continue;
            };
            let protocol = match port.get("Type").and_then(Value::as_str) {
                Some("udp") => "udp",
                _ => "tcp",
            };
            if let (Ok(container), Ok(host)) = (u16::try_from(container), u16::try_from(host)) {
                ports.insert((service.clone(), container, host, protocol));
            }
        }
        containers.push((service, name, state, health));
    }
    containers.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    Ok((
        containers
            .into_iter()
            .map(|(service, name, state, health)| {
                json!({"name": name, "service": service, "state": state, "health": health})
            })
            .collect(),
        ports
            .into_iter()
            .map(|(service, container_port, host_port, protocol)| {
                json!({"service": service, "container_port": container_port,
                       "host_port": host_port, "protocol": protocol})
            })
            .collect(),
    ))
}

/// The agent's tag events, as plain bounded display text: at most
/// [`MAX_TAG_EVENTS`], and only kinds the agent sends.
fn parse_tag_events(body: &[u8]) -> Vec<Value> {
    let Ok(answer) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    answer
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| {
            let text = |key: &str, limit: usize| {
                event
                    .get(key)
                    .and_then(Value::as_str)
                    .map(|text| plain(text, limit))
            };
            let kind = text("kind", 16).filter(|kind| {
                matches!(kind.as_str(), "restored" | "not_restored" | "unchecked")
            })?;
            Some(json!({
                "at": event.get("at").and_then(Value::as_u64)?,
                "workspace": text("workspace", MAX_NAME)?,
                "tag": text("tag", 255)?,
                "kind": kind,
                "detail": text("detail", 512)?,
            }))
        })
        .take(MAX_TAG_EVENTS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_engines_list_becomes_the_agreed_shape() {
        let body = br#"[
          {"Names":["/app-db-1"],"State":"running","Status":"Up 3 minutes (healthy)",
           "Labels":{"com.docker.compose.service":"db"},
           "Ports":[{"IP":"127.0.0.1","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"},
                    {"IP":"::1","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"},
                    {"IP":"127.0.0.2","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
                    {"IP":"::1","PrivatePort":81,"PublicPort":8081,"Type":"tcp"},
                    {"PrivatePort":9999,"Type":"tcp"}]},
          {"Names":["/\u001b[31mevil\n"],"State":"Run\nning","Status":"Up","Labels":{},"Ports":[]}]"#;
        let (containers, ports) = parse(body).unwrap();
        // Hostile text becomes one plain bounded line and a lowercase word.
        assert_eq!(containers[0]["name"], "[31mevil");
        assert_eq!(containers[0]["state"], "unning");
        assert_eq!(
            containers[1],
            json!({"name": "app-db-1", "service": "db", "state": "running", "health": "healthy"})
        );
        assert_eq!(
            ports,
            vec![
                json!({"service": "db", "container_port": 5432, "host_port": 5432, "protocol": "tcp"})
            ]
        );
    }

    #[test]
    fn tag_events_are_plain_bounded_and_only_the_kinds_the_agent_sends() {
        let many: Vec<Value> = (0..100)
            .map(|at| json!({"at": at, "workspace": "lane-b", "tag": "t:1", "kind": "restored", "detail": "x"}))
            .collect();
        let body = json!({"events": many}).to_string();
        assert_eq!(parse_tag_events(body.as_bytes()).len(), 64);
        let body = json!({"events": [
            {"at": 1, "workspace": "w\u{1b}[31m", "tag": "t:1", "kind": "restored", "detail": "a\nb"},
            {"at": 2, "workspace": "w", "tag": "t:1", "kind": "deleted", "detail": ""},
            {"at": "x", "workspace": "w", "tag": "t:1", "kind": "restored", "detail": ""},
            {"at": 3, "workspace": "w", "tag": "t:1", "kind": "unchecked"}
        ]})
        .to_string();
        assert_eq!(
            parse_tag_events(body.as_bytes()),
            vec![
                json!({"at": 1, "workspace": "w[31m", "tag": "t:1", "kind": "restored", "detail": "ab"})
            ]
        );
        assert_eq!(parse_tag_events(b"not json").len(), 0);
    }

    /// The real request and answer parsing over a socket: the agent's answer is
    /// read; an agent that does not know the route (it refuses with 403) or that
    /// answers nothing readable gives no events and does not fail the status.
    #[test]
    fn the_events_are_read_over_a_stream_and_an_old_agent_gives_none() {
        let serve = |reply: &'static str| {
            let (mut client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
            let handle = thread::spawn(move || {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    server.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                server.write_all(reply.as_bytes()).unwrap();
                String::from_utf8(request).unwrap()
            });
            let body = exchange(&mut client, TAG_EVENTS_PATH);
            (handle.join().unwrap(), body)
        };
        let json = r#"{"events":[{"at":5,"workspace":"lane-b","tag":"base-app:1","kind":"restored","detail":"d"}]}"#;
        let (request, body) = serve(Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{json}",
                json.len()
            )
            .into_boxed_str(),
        ));
        assert!(request.starts_with("GET /_marsh/tag-events HTTP/1.1\r\n"));
        assert_eq!(parse_tag_events(&body.unwrap()).len(), 1);
        let (_, refused) = serve("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        assert!(refused.is_err());
        assert_eq!(
            refused
                .map(|body| parse_tag_events(&body))
                .unwrap_or_default()
                .len(),
            0
        );
    }

    /// A stand-in for the status channel: a stream whose far end answers each
    /// request by path, and records what was asked.
    struct Fake {
        answers: Vec<(&'static str, &'static str)>,
        asked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Channel for Fake {
        fn open(&self) -> Result<Opened, String> {
            let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
            let (answers, asked) = (self.answers.clone(), self.asked.clone());
            thread::spawn(move || {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if server.read_exact(&mut byte).is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let path = request.split(' ').nth(1).unwrap_or("").to_owned();
                asked
                    .lock()
                    .unwrap()
                    .push(request.lines().next().unwrap().to_owned());
                let reply = answers.iter().find(|(p, _)| *p == path).map_or(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_owned(),
                    |(_, body)| {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                    },
                );
                let _ = server.write_all(reply.as_bytes());
            });
            let closer = client.try_clone().unwrap();
            Ok((
                Box::new(client),
                Box::new(move || {
                    let _ = closer.shutdown(std::net::Shutdown::Both);
                }),
            ))
        }
    }

    const EVENTS: &str =
        r#"{"events":[{"at":5,"workspace":"b","tag":"t:1","kind":"unchecked","detail":"d"}]}"#;

    /// The real read over a stream: the containers first and then the events
    /// (both as `GET`s the agent can route); an agent that refuses the events
    /// route (an older one) still gives the containers.
    #[test]
    fn the_view_has_the_events_and_survives_an_agent_that_has_none() {
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let new_agent = Fake {
            answers: vec![("/containers/json?all=1", "[]"), (TAG_EVENTS_PATH, EVENTS)],
            asked: asked.clone(),
        };
        let view = read(&new_agent).unwrap();
        assert_eq!(view.tag_events.len(), 1);
        assert_eq!(
            *asked.lock().unwrap(),
            [
                "GET /containers/json?all=1 HTTP/1.1",
                "GET /_marsh/tag-events HTTP/1.1"
            ]
        );
        let old_agent = Fake {
            answers: vec![("/containers/json?all=1", "[]")],
            asked: asked.clone(),
        };
        let view = read(&old_agent).unwrap();
        assert_eq!(view.tag_events.len(), 0);
        let down = Fake {
            answers: vec![],
            asked,
        };
        assert!(read(&down).is_err());
    }

    #[test]
    fn a_chunked_answer_is_read_whole() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n[1,2\r\n2\r\n]\n\r\n0\r\n\r\n";
        assert_eq!(response(&mut &wire[..]).unwrap(), b"[1,2]\n");
        let sized = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n[]\n";
        assert_eq!(response(&mut &sized[..]).unwrap(), b"[]\n");
        assert!(response(&mut &b"HTTP/1.1 403 Forbidden\r\n\r\n"[..]).is_err());
    }
}
