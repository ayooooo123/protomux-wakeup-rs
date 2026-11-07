//! npm protomux-wakeup on Hyperswarm against this crate on a peeroxide swarm,
//! on a local HyperDHT testnet over UDX. Needs `npm install` in `tests/js`.

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hypercore::crypto::discovery_key;
use peeroxide::{JoinOpts, SwarmConfig, SwarmConnection, SwarmHandle, spawn};
use peeroxide_dht::hyperdht::HyperDhtConfig;
use peeroxide_dht::rpc::DhtConfig;
use protomux::Mux;
use protomux_wakeup::{
    Lookup, SessionHandlers, WakeupOptions, WakeupPeer, WakeupSession, WakeupSwarm, wakeup::Writer_,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Notify, mpsc};
use tokio::time::timeout;

fn js_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn writers_hex(writers: &[Writer_]) -> String {
    writers
        .iter()
        .map(|w| format!("{}:{}", hex(&w.key), w.length))
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Default)]
struct Log {
    events: Mutex<Vec<String>>,
    notify: Notify,
    peer: Mutex<Option<WakeupPeer>>,
}

impl Log {
    fn push(&self, event: String) {
        self.events.lock().unwrap().push(event);
        self.notify.notify_waiters();
    }

    fn has(&self, prefix: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.starts_with(prefix))
    }

    async fn wait_for(&self, prefix: &str) -> String {
        self.wait_count(prefix, 1).await
    }

    async fn wait_count(&self, prefix: &str, count: usize) -> String {
        timeout(Duration::from_secs(60), async {
            loop {
                let notified = self.notify.notified();
                let found = {
                    let events = self.events.lock().unwrap();
                    if let Some(error) = events.iter().find(|e| e.starts_with("error")) {
                        panic!("node error: {error}");
                    }
                    let matches: Vec<&String> =
                        events.iter().filter(|e| e.starts_with(prefix)).collect();
                    (matches.len() >= count).then(|| matches[count - 1].clone())
                };
                if let Some(event) = found {
                    return event;
                }
                notified.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "no {count}x {prefix:?} in {:?}",
                self.events.lock().unwrap()
            )
        })
    }
}

fn node(args: &[&str]) -> (Child, ChildStdin, Arc<Log>) {
    assert!(
        js_dir().join("node_modules").exists(),
        "run `npm install` in {} first",
        js_dir().display()
    );
    let mut child = Command::new("node")
        .arg("peer.js")
        .args(args)
        .current_dir(js_dir())
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node on PATH");
    let stdin = child.stdin.take().unwrap();
    let log = Arc::new(Log::default());
    let reader = log.clone();
    let stdout: ChildStdout = child.stdout.take().unwrap();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            reader.push(line);
        }
    });
    (child, stdin, log)
}

async fn send(stdin: &mut ChildStdin, command: &str) {
    stdin.write_all(command.as_bytes()).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();
    stdin.flush().await.unwrap();
}

async fn testnet() -> (Child, ChildStdin, String) {
    let (child, stdin, log) = node(&["testnet"]);
    let line = log.wait_for("bootstrap ").await;
    let port = line.trim_start_matches("bootstrap ").trim().to_owned();
    (child, stdin, port)
}

async fn rust_swarm(bootstrap_port: &str) -> (SwarmHandle, mpsc::Receiver<SwarmConnection>) {
    let mut dht = DhtConfig::default();
    dht.bootstrap = vec![format!("127.0.0.1:{bootstrap_port}")];
    dht.host = "127.0.0.1".to_string();
    dht.port = 0;
    let mut hyper = HyperDhtConfig::default();
    hyper.dht = dht;
    let mut config = SwarmConfig::default();
    config.dht = hyper;
    let (_task, handle, conns) = spawn(config).await.expect("peeroxide swarm");
    (handle, conns)
}

struct RustPeer {
    _wakeup: Arc<WakeupSwarm>,
    session: WakeupSession,
    log: Arc<Log>,
    muxes: Arc<Mutex<Vec<Mux>>>,
    _swarm: SwarmHandle,
}

impl RustPeer {
    fn peer(&self) -> WakeupPeer {
        self.log.peer.lock().unwrap().clone().expect("peer added")
    }
}

async fn rust_peer(
    bootstrap_port: &str,
    capability: [u8; 32],
    session_key: Option<[u8; 32]>,
) -> RustPeer {
    let log = Arc::new(Log::default());
    let (wakeup_log, add_log, add_peer, remove_log) =
        (log.clone(), log.clone(), log.clone(), log.clone());
    let (active_log, inactive_log, lookup_log, announce_log, destroy_log) = (
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
    );
    let swarm = Arc::new(WakeupSwarm::with_options(
        move |id, _mux| wakeup_log.push(format!("wakeup {}", hex(id))),
        WakeupOptions::default(),
    ));
    let session = swarm.session(
        capability,
        SessionHandlers {
            discovery_key: session_key,
            on_peeradd: Some(Box::new(move |peer, _| {
                *add_peer.peer.lock().unwrap() = Some(peer.clone());
                add_log.push("peeradd".into());
            })),
            on_peerremove: Some(Box::new(move |_, _| remove_log.push("peerremove".into()))),
            on_peeractive: Some(Box::new(move |_, _| active_log.push("peeractive".into()))),
            on_peerinactive: Some(Box::new(move |_, _| {
                inactive_log.push("peerinactive".into());
            })),
            on_lookup: Some(Box::new(move |req, _, _| {
                let hash = match &req.hash {
                    None => "none".to_owned(),
                    Some(hash) => hex(hash),
                };
                lookup_log.push(format!("lookup {hash}"));
            })),
            on_announce: Some(Box::new(move |writers, _, _| {
                announce_log.push(format!("announce {}", writers_hex(writers)));
            })),
            on_destroy: Some(Box::new(move |_| destroy_log.push("destroy".into()))),
            ..Default::default()
        },
    );

    let (handle, mut conns) = rust_swarm(bootstrap_port).await;
    let muxes: Arc<Mutex<Vec<Mux>>> = Arc::new(Mutex::new(Vec::new()));
    let add_swarm = swarm.clone();
    let add_muxes = muxes.clone();
    tokio::spawn(async move {
        while let Some(conn) = conns.recv().await {
            let mux = Mux::from_secret_stream(conn.peer.stream);
            add_swarm.add_stream(&mux);
            add_muxes.lock().unwrap().push(mux);
        }
    });

    let topic = session_key.unwrap_or_else(|| discovery_key(&capability));
    let mut opts = JoinOpts::default();
    opts.server = false;
    opts.client = true;
    handle.join(topic, opts).await.expect("join topic");
    handle.flush().await.expect("flush");

    RustPeer {
        _wakeup: swarm,
        session,
        log,
        muxes,
        _swarm: handle,
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    timeout(Duration::from_secs(60), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn js_announces_and_rust_answers_lookups() {
    let (_testnet, _testnet_in, port) = testnet().await;
    let capability = [0x11; 32];
    let (_js, mut js_in, js) = node(&["peer", &port, &hex(&capability)]);
    js.wait_for("joined").await;

    let rust = rust_peer(&port, capability, None).await;
    js.wait_for("peer-add").await;
    rust.log.wait_for("peeradd").await;

    // JS announces; Rust's onannounce must see the same keys and lengths.
    let announced = vec![
        Writer_ {
            key: [0xaa; 32],
            length: 77,
        },
        Writer_ {
            key: [0xab; 32],
            length: 0,
        },
    ];
    send(&mut js_in, &format!("announce {}", writers_hex(&announced))).await;
    js.wait_for("sent-announce").await;
    assert_eq!(
        rust.log.wait_for("announce ").await,
        format!("announce {}", writers_hex(&announced))
    );

    // Lookup without a hash, answered from the Rust side.
    let reply = vec![Writer_ {
        key: [0xbb; 32],
        length: 5,
    }];
    send(&mut js_in, "lookup none").await;
    js.wait_for("sent-lookup").await;
    rust.log.wait_for("lookup none").await;
    rust.session.announce(&rust.peer(), &reply);
    assert_eq!(
        js.wait_for("announce ").await,
        format!("announce {}", writers_hex(&reply))
    );

    // Lookup with a hash, answered too.
    let hash = [0xcc; 32];
    send(&mut js_in, &format!("lookup {}", hex(&hash))).await;
    js.wait_count("sent-lookup", 2).await;
    rust.log.wait_for(&format!("lookup {}", hex(&hash))).await;
    rust.session.announce(&rust.peer(), &reply);
    js.wait_count("announce ", 2).await;

    // Info: active flips propagate to JS.
    rust.session.inactive();
    js.wait_for("peer-inactive").await;
    rust.session.active();
    js.wait_count("peer-active", 2).await;

    // Closing the stream fires peer-remove.
    send(&mut js_in, "close").await;
    js.wait_for("closed").await;
    rust.log.wait_for("peerremove").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn rust_announces_and_js_answers_lookups() {
    let (_testnet, _testnet_in, port) = testnet().await;
    let capability = [0x12; 32];
    let (_js, mut js_in, js) = node(&["peer", &port, &hex(&capability)]);
    js.wait_for("joined").await;

    let rust = rust_peer(&port, capability, None).await;
    rust.log.wait_for("peeradd").await;
    js.wait_for("peer-add").await;

    let announced = vec![Writer_ {
        key: [0xdd; 32],
        length: 99,
    }];
    rust.session.announce(&rust.peer(), &announced);
    assert_eq!(
        js.wait_for("announce ").await,
        format!("announce {}", writers_hex(&announced))
    );

    // Rust looks up (once per API); JS answers with its fixed writer set.
    let answer = format!("announce {hex_5a}:3", hex_5a = hex(&[0x5a; 32]));
    rust.session.lookup(&rust.peer(), &Lookup { hash: None });
    js.wait_for("lookup none").await;
    js.wait_for("answered-lookup").await;
    assert_eq!(rust.log.wait_for("announce ").await, answer);

    let hash = [0xff; 32];
    rust.session.broadcast_lookup(&Lookup { hash: Some(hash) });
    js.wait_for(&format!("lookup {}", hex(&hash))).await;
    js.wait_count("answered-lookup", 2).await;
    assert_eq!(rust.log.wait_count("announce ", 2).await, answer);

    // JS activity reaches Rust.
    send(&mut js_in, "inactive").await;
    js.wait_for("sent-inactive").await;
    rust.log.wait_for("peerinactive").await;
    assert!(!rust.peer().is_active());
    send(&mut js_in, "active").await;
    js.wait_for("sent-active").await;
    rust.log.wait_count("peeractive", 2).await;

    // Closing the Rust stream fires peer-remove on the JS side.
    wait_until(|| !rust.muxes.lock().unwrap().is_empty(), "mux").await;
    rust.muxes.lock().unwrap()[0].destroy();
    js.wait_for("peer-remove").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn capability_mismatch_is_rejected_by_both_sides() {
    let (_testnet, _testnet_in, port) = testnet().await;
    let rust_capability = [0x21; 32];
    let js_capability = [0x22; 32];
    let topic = discovery_key(&rust_capability);
    let (_js, mut js_in, js) = node(&["peer", &port, &hex(&js_capability), &hex(&topic)]);
    js.wait_for("joined").await;

    let rust = rust_peer(&port, rust_capability, Some(topic)).await;
    js.wait_for("connection").await;
    wait_until(|| !rust.muxes.lock().unwrap().is_empty(), "mux").await;
    let mux = rust.muxes.lock().unwrap()[0].clone();
    wait_until(
        || rust.session.get_peer(&mux).is_none(),
        "rust channel rejected",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    send(&mut js_in, "state").await;
    assert_eq!(js.wait_for("state ").await, "state peers=0 pending=0");
    assert!(!rust.log.has("peeradd"));
    assert!(!js.has("peer-add"));
    assert!(!js.has("peer-remove"));
    assert!(rust.session.peers().is_empty());
}
