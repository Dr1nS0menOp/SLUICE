//! Replaying archived events to a destination: every event once, as archived, in batches.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Value, json};
use sluice_archive::{ArchiveError, Query, Scan, replay};

/// One request the receiver got: its content type and body.
type Received = Arc<Mutex<Vec<(String, String)>>>;

/// An HTTP receiver that answers each request with the next of `statuses` (then 200) and
/// records it.
fn receiver(statuses: Vec<u16>) -> (String, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let url = format!("http://{}/ingest", listener.local_addr().expect("bound"));
    let received: Received = Arc::default();
    let seen = Arc::clone(&received);
    thread::spawn(move || {
        let mut statuses = statuses.into_iter();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = BufReader::new(stream);
            // Requests on one connection, one after another (keep-alive).
            while let Some((content_type, body)) = request(&mut reader) {
                seen.lock()
                    .expect("not poisoned")
                    .push((content_type, body));
                let status = statuses.next().unwrap_or(200);
                let answer = format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n");
                if reader.get_mut().write_all(answer.as_bytes()).is_err() {
                    break;
                }
            }
        }
    });
    (url, received)
}

/// Reads one request; `None` when the connection is closed.
fn request(reader: &mut impl BufRead) -> Option<(String, String)> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let (mut length, mut content_type) = (0, String::new());
    loop {
        line.clear();
        reader.read_line(&mut line).ok()?;
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().ok()?;
            } else if name.eq_ignore_ascii_case("content-type") {
                value.trim().clone_into(&mut content_type);
            }
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some((content_type, String::from_utf8(body).ok()?))
}

fn archive(name: &str, events: &[Value]) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("replay-{name}"));
    let _ = fs::remove_dir_all(&root);
    let dir = root.join("s/2026-10-09");
    fs::create_dir_all(&dir).expect("creating the archive");
    if !events.is_empty() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        for event in events {
            writeln!(encoder, "{event}").expect("writing to memory");
        }
        let bytes = encoder.finish().expect("writing to memory");
        fs::write(dir.join("17.ndjson.gz"), bytes).expect("writing the file");
    }
    root
}

fn events(n: u64) -> Vec<Value> {
    (0..n)
        .map(|i| json!({"n": i, "Message": "a \"quoted\"\nline", "timestamp": "2026-10-09T17:00:00Z"}))
        .collect()
}

fn scan(root: &Path) -> Scan {
    Scan::new(root, Query::default()).expect("the archive exists")
}

#[test]
fn every_event_goes_out_once_as_archived_in_batches() {
    let archived = events(5);
    let root = archive("batches", &archived);
    let (url, received) = receiver(Vec::new());
    assert_eq!(replay(&mut scan(&root), &url, 2).expect("replays"), 5);

    let received = received.lock().unwrap().clone();
    let sizes: Vec<usize> = received.iter().map(|(_, b)| b.lines().count()).collect();
    assert_eq!(sizes, [2, 2, 1]);
    assert!(received.iter().all(|(t, _)| t == "application/x-ndjson"));
    let sent: Vec<Value> = received
        .iter()
        .flat_map(|(_, body)| body.lines().map(|l| serde_json::from_str(l).unwrap()))
        .collect();
    assert_eq!(sent, archived);
}

#[test]
fn a_batch_of_zero_sends_one_event_per_request() {
    let root = archive("zero", &events(2));
    let (url, received) = receiver(Vec::new());
    assert_eq!(replay(&mut scan(&root), &url, 0).expect("replays"), 2);
    assert_eq!(received.lock().unwrap().len(), 2);
}

#[test]
fn an_empty_archive_sends_nothing() {
    let root = archive("empty", &[]);
    let (url, received) = receiver(Vec::new());
    assert_eq!(replay(&mut scan(&root), &url, 10).expect("replays"), 0);
    assert!(received.lock().unwrap().is_empty());
}

#[test]
fn the_first_failed_request_stops_the_replay_and_says_how_many_arrived() {
    let root = archive("failed", &events(5));
    let (url, received) = receiver(vec![200, 500]);
    let error = replay(&mut scan(&root), &url, 2).unwrap_err();
    assert!(
        matches!(&error, ArchiveError::Replay { sent: 2, url: u, .. } if *u == url),
        "{error:?}"
    );
    assert_eq!(
        received.lock().unwrap().len(),
        2,
        "nothing after the failure"
    );
}
