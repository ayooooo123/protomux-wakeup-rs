//! Rust peers over the in-memory transport: handshake, messages, activity, GC.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use protomux::{ChannelOptions, Mux, StreamInfo, memory};
use protomux_wakeup::{
    Handshake, Info, Lookup, SessionHandlers, WakeupOptions, WakeupPeer, WakeupSession,
    WakeupSwarm, wakeup::Writer_,
};
use tokio::sync::Notify;
use tokio::time::timeout;

type PeerSlot = Arc<Mutex<Option<WakeupPeer>>>;

#[derive(Default)]
struct Log {
    events: Mutex<Vec<String>>,
    notify: Notify,
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
        timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.notify.notified();
                let found = {
                    let events = self.events.lock().unwrap();
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

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

struct Node {
    swarm: WakeupSwarm,
    log: Arc<Log>,
    peer: PeerSlot,
}

impl Node {
    fn new(options: WakeupOptions) -> Self {
        let log = Arc::new(Log::default());
        let swarm_log = log.clone();
        let swarm = WakeupSwarm::with_options(
            move |id, _mux| swarm_log.push(format!("wakeup {}", hex(id))),
            options,
        );
        Self {
            swarm,
            log,
            peer: Arc::new(Mutex::new(None)),
        }
    }

    fn session(
        &self,
        capability: [u8; 32],
        discovery_key: Option<[u8; 32]>,
        active: bool,
    ) -> WakeupSession {
        let (add_log, add_peer) = (self.log.clone(), self.peer.clone());
        let remove_log = self.log.clone();
        let active_log = self.log.clone();
        let inactive_log = self.log.clone();
        let lookup_log = self.log.clone();
        let announce_log = self.log.clone();
        let destroy_log = self.log.clone();
        self.swarm.session(
            capability,
            SessionHandlers {
                discovery_key,
                active,
                on_peeradd: Some(Box::new(move |peer, _| {
                    *add_peer.lock().unwrap() = Some(peer.clone());
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
            },
        )
    }

    fn peer(&self) -> WakeupPeer {
        self.peer.lock().unwrap().clone().expect("peer added")
    }
}

fn mux_pair(handshake_hash: [u8; 64]) -> (Mux, Mux) {
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let info = |is_initiator| StreamInfo {
        is_initiator,
        handshake_hash: Some(handshake_hash),
        remote_public_key: None,
    };
    (Mux::new(ar, aw, info(true)), Mux::new(br, bw, info(false)))
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

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn writers() -> Vec<Writer_> {
    vec![
        Writer_ {
            key: [0x11; 32],
            length: 7,
        },
        Writer_ {
            key: [0x22; 32],
            length: 0,
        },
    ]
}

fn proof(capability: &[u8; 32], handshake_hash: &[u8; 64], ns: usize) -> [u8; 32] {
    let namespace = hypercore::crypto::namespace(b"wakeup", 2);
    hypercore::crypto::hash(&[&namespace[ns], capability, handshake_hash])
}

#[tokio::test]
async fn announce_lookup_activity_and_close() {
    let (mux_a, mux_b) = mux_pair([0x42; 64]);
    let a = Node::new(WakeupOptions::default());
    let b = Node::new(WakeupOptions::default());
    let a_session = a.session([1; 32], None, true);
    let b_session = b.session([1; 32], None, true);
    a.swarm.add_stream(&mux_a);
    b.swarm.add_stream(&mux_b);
    a.log.wait_for("peeradd").await;
    b.log.wait_for("peeradd").await;

    assert!(a.swarm.has_stream(&mux_a));
    assert!(a_session.has_stream(&mux_a));
    assert_eq!(a.swarm.get_sessions(&[1; 32]).len(), 1);
    assert_eq!(a_session.peers().len(), 1);
    assert!(a.peer().is_active());

    let expected = format!("announce {}", writers_hex(&writers()));
    a_session.announce_by_stream(&mux_a, &writers());
    assert_eq!(b.log.wait_for("announce ").await, expected);

    b_session.lookup_by_stream(&mux_b, &Lookup { hash: None });
    a.log.wait_for("lookup none").await;
    a_session.announce(&a.peer(), &writers());
    b.log.wait_count("announce ", 2).await;

    b_session.broadcast_lookup(&Lookup {
        hash: Some([0x33; 32]),
    });
    a.log
        .wait_for(&format!("lookup {}", hex(&[0x33; 32])))
        .await;

    a_session.inactive();
    b.log.wait_for("peerinactive").await;
    assert!(!b.peer().is_active());
    a_session.active();
    b.log.wait_count("peeractive", 2).await;
    assert!(b.peer().is_active());

    mux_a.destroy();
    b.log.wait_count("peerinactive", 2).await;
    b.log.wait_for("peerremove").await;
    assert!(b_session.peers().is_empty());
    wait_until(|| !a.swarm.has_stream(&mux_a), "stream removal").await;
}

#[tokio::test]
async fn capability_mismatch_closes_channel() {
    let discovery_key = [5; 32];
    let (mux_a, mux_b) = mux_pair([0x44; 64]);
    let a = Node::new(WakeupOptions::default());
    let b = Node::new(WakeupOptions::default());
    let a_session = a.session([1; 32], Some(discovery_key), true);
    let b_session = b.session([2; 32], Some(discovery_key), true);
    a.swarm.add_stream(&mux_a);
    assert!(a_session.get_peer(&mux_a).is_some());
    b.swarm.add_stream(&mux_b);
    assert!(b_session.get_peer(&mux_b).is_some());

    wait_until(
        || a_session.get_peer(&mux_a).is_none() && b_session.get_peer(&mux_b).is_none(),
        "both channels closed",
    )
    .await;
    assert!(!a.log.has("peeradd"));
    assert!(!b.log.has("peeradd"));
    assert!(a_session.peers().is_empty() && b_session.peers().is_empty());
}

#[tokio::test]
async fn gc_tears_down_idle_topic_after_five_ticks() {
    let options = WakeupOptions {
        gc_tick_time: Duration::from_millis(30),
    };
    let (mux_a, mux_b) = mux_pair([0x45; 64]);
    let a = Node::new(options.clone());
    let b = Node::new(options.clone());
    let a_session = a.session([3; 32], None, true);
    let b_session = b.session([3; 32], None, true);
    a.swarm.add_stream(&mux_a);
    b.swarm.add_stream(&mux_b);
    a.log.wait_for("peeradd").await;
    b.log.wait_for("peeradd").await;
    a_session.inactive();
    b_session.inactive();
    a.log.wait_for("peerinactive").await;
    b.log.wait_for("peerinactive").await;
    assert!(!a.peer().is_active());

    // No sessions and no active peers left: the topic waits for the GC.
    a_session.destroy();
    assert!(a_session.is_destroyed());
    tokio::time::sleep(Duration::from_millis(60)).await; // two ticks
    assert!(!b.log.has("peerremove"));

    // Teardown on the fifth tick closes the channel; destroying a session
    // does not run its destroy handler (JS does the same).
    b.log.wait_for("peerremove").await;
    assert!(!a.log.has("destroy"));

    // B still has a session, so its topic outlives the ticks.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(b.swarm.get_sessions(&[3; 32]).len(), 1);
    assert!(b_session.get_peer(&mux_b).is_none());
}

#[tokio::test]
async fn swarm_destroy_calls_on_destroy() {
    let a = Node::new(WakeupOptions::default());
    let session = a.session([9; 32], None, true);
    a.swarm.destroy();
    a.log.wait_for("destroy").await;
    // As in JS, teardown does not mark the session destroyed.
    assert!(!session.is_destroyed());
    assert!(a.swarm.get_sessions(&[9; 32]).is_empty());
}

#[tokio::test]
async fn unknown_topic_invokes_onwakeup() {
    let (mux_a, mux_b) = mux_pair([0x46; 64]);
    let b = Node::new(WakeupOptions::default());
    b.swarm.add_stream(&mux_b);
    let a = Node::new(WakeupOptions::default());
    let _a_session = a.session([7; 32], None, true);
    a.swarm.add_stream(&mux_a);

    // A opened its topic on B, which has no session for it.
    let expected = format!("wakeup {}", hex(&crypto_discovery_key(&[7; 32])));
    b.log.wait_for(&expected).await;
}

/// `hypercore-crypto` discovery key, via the same computation the swarm uses.
fn crypto_discovery_key(capability: &[u8; 32]) -> [u8; 32] {
    hypercore::crypto::discovery_key(capability)
}

#[tokio::test]
async fn wrong_capability_batch_reaches_no_handlers() {
    let handshake_hash = [0x47; 64];
    let (mux_a, mux_b) = mux_pair(handshake_hash);
    let b = Node::new(WakeupOptions::default());
    let capability = [7; 32];
    let session = b.session(capability, None, true);
    b.swarm.add_stream(&mux_b);

    let id = crypto_discovery_key(&capability);
    let handshake = compact_encoding::encode(&Handshake {
        version: 0,
        capability: [0; 32],
        active: true,
    });
    mux_a.cork();
    let channel = mux_a
        .open_channel(ChannelOptions {
            id: Some(&id),
            handshake: &handshake,
            ..ChannelOptions::new("wakeup")
        })
        .unwrap();
    channel.send(2, &Info { active: true });
    channel.send(1, &writers());
    channel.send(0, &Lookup { hash: None });
    mux_a.uncork();

    wait_until(
        || session.get_peer(&mux_b).is_none(),
        "rejected wakeup peer removal",
    )
    .await;
    assert!(!b.log.has("peer"));
    assert!(!b.log.has("lookup"));
    assert!(!b.log.has("announce"));
}

#[tokio::test]
async fn passive_session_does_not_open_on_existing_muxes() {
    let (mux_a, mux_b) = mux_pair([0x48; 64]);
    let a = Node::new(WakeupOptions::default());
    let b = Node::new(WakeupOptions::default());
    a.swarm.add_stream(&mux_a);
    b.swarm.add_stream(&mux_b);

    let capability = [8; 32];
    let _session = a.session(capability, None, false);
    let expected = format!("wakeup {}", hex(&crypto_discovery_key(&capability)));
    assert!(
        timeout(Duration::from_millis(100), b.log.wait_for(&expected))
            .await
            .is_err(),
        "a passive session opened an existing mux"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_then_reopen_wakeup_channel_stays_live() {
    let handshake_hash = [0x49; 64];
    let (mux_a, mux_b) = mux_pair(handshake_hash);
    let b = Node::new(WakeupOptions::default());
    let capability = [9; 32];
    let _session = b.session(capability, None, true);
    b.swarm.add_stream(&mux_b);

    let id = crypto_discovery_key(&capability);
    let handshake = compact_encoding::encode(&Handshake {
        version: 0,
        capability: proof(&capability, &handshake_hash, 0),
        active: true,
    });
    let first = mux_a
        .open_channel(ChannelOptions {
            id: Some(&id),
            handshake: &handshake,
            ..ChannelOptions::new("wakeup")
        })
        .unwrap();
    let mut first = first;
    first.opened().await.unwrap();

    mux_a.cork();
    first.close();
    let mut second = mux_a
        .open_channel(ChannelOptions {
            id: Some(&id),
            handshake: &handshake,
            ..ChannelOptions::new("wakeup")
        })
        .unwrap();
    mux_a.uncork();
    assert!(
        second.opened().await.is_some(),
        "the reopened wakeup channel was rejected"
    );
}

#[tokio::test]
async fn discovery_key_override_is_available_by_id() {
    let swarm = WakeupSwarm::new(|_, _| {});
    let capability = [10; 32];
    let discovery_key = [11; 32];
    let session = swarm.session(
        capability,
        SessionHandlers {
            discovery_key: Some(discovery_key),
            ..Default::default()
        },
    );
    assert!(swarm.get_sessions(&capability).is_empty());
    assert_eq!(swarm.get_sessions_by_id(&discovery_key).len(), 1);
    session.destroy();
}

#[tokio::test]
async fn teardown_notifies_peers_before_destroy() {
    let (mux_a, mux_b) = mux_pair([0x50; 64]);
    let a = Node::new(WakeupOptions::default());
    let b = Node::new(WakeupOptions::default());
    let _a_session = a.session([12; 32], None, true);
    let _b_session = b.session([12; 32], None, true);
    a.swarm.add_stream(&mux_a);
    b.swarm.add_stream(&mux_b);
    b.log.wait_for("peeradd").await;

    b.swarm.destroy();
    b.log.wait_for("destroy").await;
    let events = b.log.events();
    let inactive = events
        .iter()
        .position(|event| event == "peerinactive")
        .unwrap();
    let removed = events
        .iter()
        .position(|event| event == "peerremove")
        .unwrap();
    let destroyed = events.iter().position(|event| event == "destroy").unwrap();
    assert!(inactive < removed && removed < destroyed);
}
