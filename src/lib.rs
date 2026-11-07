#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use compact_encoding::Codec;
use hypercore::crypto;
use protomux::{Channel, ChannelOptions, ChannelSender, Event, Mux, PairRequest};
use tokio::sync::Notify;

mod encoding {
    include!(concat!(env!("OUT_DIR"), "/wakeup.rs"));
}

pub use encoding::wakeup;
pub use encoding::wakeup::{Announce, Handshake, Info, Lookup, Writer_};

/// The Protomux protocol every wakeup channel opens.
const PROTOCOL: &str = "wakeup";
/// Channel message kinds, in schema order.
const LOOKUP: u64 = 0;
const ANNOUNCE: u64 = 1;
const INFO: u64 = 2;
/// Idle ticks before a topic is torn down, as in JS.
const GC_TICKS: u32 = 5;

type OnPeer = Box<dyn Fn(&WakeupPeer, &WakeupSession) + Send + Sync>;
type OnLookup = Box<dyn Fn(&Lookup, &WakeupPeer, &WakeupSession) + Send + Sync>;
type OnAnnounce = Box<dyn Fn(&[Writer_], &WakeupPeer, &WakeupSession) + Send + Sync>;
type OnDestroy = Box<dyn Fn(&WakeupSession) + Send + Sync>;
type OnWakeup = Box<dyn Fn(&[u8], &Mux) + Send + Sync>;

/// Options for [`WakeupSwarm`].
#[derive(Debug, Clone)]
pub struct WakeupOptions {
    /// GC tick; a topic without sessions or active peers dies after `GC_TICKS` ticks.
    pub gc_tick_time: Duration,
}

impl Default for WakeupOptions {
    fn default() -> Self {
        // JS runs setInterval(_gc, 2000) only while topics wait: same 5-tick teardown.
        Self {
            gc_tick_time: Duration::from_millis(2000),
        }
    }
}

/// Callbacks a session receives. Mirrors the JS handlers object.
pub struct SessionHandlers {
    /// Topic id; defaults to the discovery key of the capability.
    pub discovery_key: Option<[u8; 32]>,
    /// Whether the session starts active (JS `active !== false`).
    pub active: bool,
    pub on_peeradd: Option<OnPeer>,
    pub on_peerremove: Option<OnPeer>,
    pub on_peeractive: Option<OnPeer>,
    pub on_peerinactive: Option<OnPeer>,
    pub on_lookup: Option<OnLookup>,
    pub on_announce: Option<OnAnnounce>,
    pub on_destroy: Option<OnDestroy>,
}

impl Default for SessionHandlers {
    fn default() -> Self {
        Self {
            discovery_key: None,
            active: true,
            on_peeradd: None,
            on_peerremove: None,
            on_peeractive: None,
            on_peerinactive: None,
            on_lookup: None,
            on_announce: None,
            on_destroy: None,
        }
    }
}

/// A remote peer on one topic. Cheap to clone; methods are safe after removal.
#[derive(Clone)]
pub struct WakeupPeer(Arc<PeerData>);

struct PeerData {
    channel: ChannelSender,
    stream: Mux,
    active: AtomicBool,
    pending: AtomicBool,
}

impl WakeupPeer {
    /// The mux this peer reached us over, the JS `peer.stream`.
    pub fn stream(&self) -> &Mux {
        &self.0.stream
    }

    pub fn is_active(&self) -> bool {
        self.0.active.load(Ordering::Relaxed)
    }

    pub fn is_pending(&self) -> bool {
        self.0.pending.load(Ordering::Relaxed)
    }

    fn set_active(&self, active: bool) {
        self.0.active.store(active, Ordering::Relaxed);
    }

    fn set_pending(&self, pending: bool) {
        self.0.pending.store(pending, Ordering::Relaxed);
    }

    fn send<T: Codec>(&self, kind: u64, msg: &T) -> bool {
        self.0.channel.send(kind, msg)
    }

    fn close(&self) {
        self.0.channel.close();
    }
}

/// A handle on one topic's session. Cloning shares the session.
#[derive(Clone)]
pub struct WakeupSession {
    swarm: Weak<Inner>,
    id: [u8; 32],
    data: Arc<SessionData>,
}

struct SessionData {
    handlers: SessionHandlers,
    active: AtomicBool,
    destroyed: AtomicBool,
}

impl WakeupSession {
    /// Topic id: the discovery key (or the handlers' override).
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Non-pending peers, in add order.
    pub fn peers(&self) -> Vec<WakeupPeer> {
        self.topic(|t| t.peers.clone()).unwrap_or_default()
    }

    /// Whether a channel for this topic is open (or opening) on `mux`.
    pub fn has_stream(&self, mux: &Mux) -> bool {
        self.get_peer(mux).is_some()
    }

    pub fn get_peer(&self, mux: &Mux) -> Option<WakeupPeer> {
        self.topic(|t| {
            t.by_stream
                .iter()
                .find(|(m, _)| same_mux(m, mux))
                .map(|(_, p)| p.clone())
        })
        .flatten()
    }

    /// Opens a channel for this topic on `mux` (JS `session.addStream`).
    pub fn add_stream(&self, mux: &Mux) {
        let Some(inner) = self.swarm.upgrade() else {
            return;
        };
        inner.open(&self.id, mux, false);
    }

    pub fn broadcast_lookup(&self, req: &Lookup) {
        let Some(inner) = self.swarm.upgrade() else {
            return;
        };
        let st = inner.lock();
        let Some(t) = st.topics.get(&self.id) else {
            return;
        };
        for peer in t.pending.iter().chain(t.peers.iter()) {
            peer.send(LOOKUP, req);
        }
    }

    pub fn lookup_by_stream(&self, mux: &Mux, req: &Lookup) {
        if let Some(peer) = self.get_peer(mux) {
            peer.send(LOOKUP, req);
        }
    }

    pub fn lookup(&self, peer: &WakeupPeer, req: &Lookup) {
        peer.send(LOOKUP, req);
    }

    /// Announces writers to one peer. `peer` may still be pending, as in JS.
    pub fn announce(&self, peer: &WakeupPeer, writers: &Announce) {
        peer.send(ANNOUNCE, writers);
    }

    /// Announces over `mux` unless that peer is still pending (JS `announceByStream`).
    pub fn announce_by_stream(&self, mux: &Mux, writers: &Announce) {
        if let Some(peer) = self.get_peer(mux)
            && !peer.is_pending()
        {
            peer.send(ANNOUNCE, writers);
        }
    }

    pub fn active(&self) {
        self.data.active.store(true, Ordering::Relaxed);
        self.bump_activity();
    }

    pub fn inactive(&self) {
        self.data.active.store(false, Ordering::Relaxed);
        self.bump_activity();
    }

    pub fn is_active(&self) -> bool {
        self.data.active.load(Ordering::Relaxed)
    }

    pub fn is_destroyed(&self) -> bool {
        self.data.destroyed.load(Ordering::Relaxed)
    }

    pub fn destroy(&self) {
        if self.data.destroyed.swap(true, Ordering::Relaxed) {
            return;
        }
        let Some(inner) = self.swarm.upgrade() else {
            return;
        };
        let effect = inner.remove_session(&self.id, self);
        inner.apply(Some(&self.id), effect);
    }

    fn is_same(&self, other: &WakeupSession) -> bool {
        Arc::ptr_eq(&self.data, &other.data)
    }

    fn topic<R>(&self, f: impl FnOnce(&Topic) -> R) -> Option<R> {
        let inner = self.swarm.upgrade()?;
        let st = inner.lock();
        st.topics.get(&self.id).map(f)
    }

    fn bump_activity(&self) {
        let Some(inner) = self.swarm.upgrade() else {
            return;
        };
        let effect = inner.bump_activity(&self.id);
        inner.apply(Some(&self.id), effect);
    }

    fn dispatch(&self, callback: Callback) {
        let handlers = &self.data.handlers;
        match callback {
            Callback::PeerAdd(peer) => {
                if let Some(f) = &handlers.on_peeradd {
                    f(&peer, self);
                }
            }
            Callback::PeerRemove(peer) => {
                if let Some(f) = &handlers.on_peerremove {
                    f(&peer, self);
                }
            }
            Callback::PeerActive(peer) => {
                if let Some(f) = &handlers.on_peeractive {
                    f(&peer, self);
                }
            }
            Callback::PeerInactive(peer) => {
                if let Some(f) = &handlers.on_peerinactive {
                    f(&peer, self);
                }
            }
            Callback::Lookup(req, peer) => {
                if let Some(f) = &handlers.on_lookup {
                    f(&req, &peer, self);
                }
            }
            Callback::Announce(writers, peer) => {
                if let Some(f) = &handlers.on_announce {
                    f(writers.as_ref(), &peer, self);
                }
            }
            Callback::Destroy => {
                if let Some(f) = &handlers.on_destroy {
                    f(self);
                }
            }
        }
    }
}

/// A wakeup swarm: one per node, shared by every topic.
pub struct WakeupSwarm {
    inner: Arc<Inner>,
}

impl WakeupSwarm {
    /// `onwakeup` sees opens for unknown or session-less topics; returning rejects.
    pub fn new(onwakeup: impl Fn(&[u8], &Mux) + Send + Sync + 'static) -> Self {
        Self::with_options(onwakeup, WakeupOptions::default())
    }

    pub fn with_options(
        onwakeup: impl Fn(&[u8], &Mux) + Send + Sync + 'static,
        options: WakeupOptions,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                onwakeup: Box::new(onwakeup),
                gc_tick: options.gc_tick_time,
                gc_running: AtomicBool::new(false),
                gc_wake: Notify::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The session for `capability`, creating its topic first when needed.
    pub fn session(&self, capability: [u8; 32], handlers: SessionHandlers) -> WakeupSession {
        let id = handlers
            .discovery_key
            .unwrap_or_else(|| crypto::discovery_key(&capability));
        let session = WakeupSession {
            swarm: Arc::downgrade(&self.inner),
            id,
            data: Arc::new(SessionData {
                active: AtomicBool::new(handlers.active),
                handlers,
                destroyed: AtomicBool::new(false),
            }),
        };
        let active = session.data.active.load(Ordering::Relaxed);
        // Registered before any channel opens, so an immediate handshake finds it.
        let mut effect = Effect::default();
        let mut muxers = Vec::new();
        {
            let mut st = self.lock();
            match st.topics.entry(id) {
                std::collections::hash_map::Entry::Vacant(vacant) => {
                    let mut topic = Topic::new(capability, active);
                    topic.sessions.push(session.clone());
                    vacant.insert(topic);
                    muxers = st.muxers.clone();
                }
                std::collections::hash_map::Entry::Occupied(mut occupied) => {
                    {
                        let topic = occupied.get_mut();
                        topic.sessions.push(session.clone());
                        let active = topic.sessions.iter().any(|s| s.is_active());
                        topic.set_active(active, &mut effect);
                    }
                    self.inner.check_gc(&mut st, &id);
                }
            }
        }
        for mux in &muxers {
            self.inner.open(&id, mux, true);
        }
        self.inner.apply(Some(&id), effect);
        session
    }

    /// Sessions on the topic `capability` resolves to.
    pub fn get_sessions(&self, capability: &[u8; 32]) -> Vec<WakeupSession> {
        let id = crypto::discovery_key(capability);
        self.lock()
            .topics
            .get(&id)
            .map(|t| t.sessions.clone())
            .unwrap_or_default()
    }

    /// Whether `mux` is one of this swarm's streams (JS `hasStream(stream)`).
    pub fn has_stream(&self, mux: &Mux) -> bool {
        self.lock().muxers.iter().any(|m| same_mux(m, mux))
    }

    /// Registers `mux` for wakeup: pairs remote opens and opens active topics.
    pub fn add_stream(&self, mux: &Mux) {
        let active_topics = {
            let mut st = self.lock();
            if st.muxers.iter().any(|m| same_mux(m, mux)) {
                return;
            }
            st.muxers.push(mux.clone());
            st.topics
                .iter()
                .filter(|(_, t)| t.is_active)
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        };
        let mut pairs = mux.pair(PROTOCOL, None);
        let inner = self.inner.clone();
        let handle = mux.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    req = pairs.recv() => match req {
                        Some(req) => inner.on_pair(&handle, req),
                        None => break,
                    },
                    _ = handle.closed() => break,
                }
            }
            inner.remove_stream(&handle);
        });
        for id in active_topics {
            self.inner.open(&id, mux, true);
        }
    }

    /// Tears every topic down and stops the GC timer.
    pub fn destroy(&self) {
        let mut effect = Effect::default();
        {
            let mut st = self.lock();
            let ids: Vec<[u8; 32]> = st.topics.keys().copied().collect();
            for id in ids {
                self.inner.teardown_locked(&mut st, &id, &mut effect);
            }
            if st.gc.is_empty() {
                self.inner.gc_wake.notify_one();
            }
        }
        self.inner.apply(None, effect);
    }
}

struct Inner {
    state: Mutex<State>,
    onwakeup: OnWakeup,
    gc_tick: Duration,
    gc_running: AtomicBool,
    gc_wake: Notify,
}

#[derive(Default)]
struct State {
    topics: HashMap<[u8; 32], Topic>,
    muxers: Vec<Mux>,
    gc: Vec<[u8; 32]>,
}

struct Topic {
    capability: [u8; 32],
    sessions: Vec<WakeupSession>,
    peers: Vec<WakeupPeer>,
    pending: Vec<WakeupPeer>,
    by_stream: Vec<(Mux, WakeupPeer)>,
    active_peers: usize,
    is_active: bool,
    idle_ticks: u32,
    gcing: bool,
    destroyed: bool,
}

impl Topic {
    fn new(capability: [u8; 32], active: bool) -> Self {
        Self {
            capability,
            sessions: Vec::new(),
            peers: Vec::new(),
            pending: Vec::new(),
            by_stream: Vec::new(),
            active_peers: 0,
            is_active: active,
            idle_ticks: 0,
            gcing: false,
            destroyed: false,
        }
    }

    fn set_active(&mut self, active: bool, effect: &mut Effect) {
        if self.is_active == active {
            return;
        }
        if active {
            self.idle_ticks = 0;
        }
        self.is_active = active;
        for peer in self.pending.iter().chain(self.peers.iter()) {
            peer.send(INFO, &Info { active });
        }
        if active {
            effect.open = true;
        }
    }
}

#[derive(Default)]
struct Effect {
    open: bool,
    callbacks: Vec<(WakeupSession, Callback)>,
}

enum Callback {
    PeerAdd(WakeupPeer),
    PeerRemove(WakeupPeer),
    PeerActive(WakeupPeer),
    PeerInactive(WakeupPeer),
    Lookup(Lookup, WakeupPeer),
    Announce(Arc<[Writer_]>, WakeupPeer),
    Destroy,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn apply(self: &Arc<Self>, id: Option<&[u8; 32]>, effect: Effect) {
        if effect.open
            && let Some(id) = id
        {
            self.open_all(id);
        }
        for (session, callback) in effect.callbacks {
            session.dispatch(callback);
        }
    }

    fn open_all(self: &Arc<Self>, id: &[u8; 32]) {
        let muxers = {
            let st = self.lock();
            match st.topics.get(id) {
                Some(t) if t.is_active && !t.destroyed => st.muxers.clone(),
                _ => return,
            }
        };
        for mux in &muxers {
            self.open(id, mux, false);
        }
    }

    fn open(self: &Arc<Self>, id: &[u8; 32], mux: &Mux, unique: bool) {
        let info = mux.stream_info().clone();
        let Some(handshake_hash) = info.handshake_hash else {
            return;
        };
        let (proof, active) = {
            let st = self.lock();
            let Some(topic) = st.topics.get(id) else {
                return;
            };
            if topic.destroyed {
                return;
            }
            if !unique && topic.by_stream.iter().any(|(m, _)| same_mux(m, mux)) {
                return;
            }
            let ns = if info.is_initiator { 0 } else { 1 };
            (
                capability(ns, &topic.capability, &handshake_hash),
                topic.is_active,
            )
        };
        let handshake = compact_encoding::encode(&Handshake {
            version: 0,
            capability: proof,
            active,
        });
        let Some(channel) = mux.open_channel(ChannelOptions {
            id: Some(id),
            handshake: &handshake,
            ..ChannelOptions::new(PROTOCOL)
        }) else {
            return;
        };
        let peer = WakeupPeer(Arc::new(PeerData {
            channel: channel.sender(),
            stream: mux.clone(),
            active: AtomicBool::new(false),
            pending: AtomicBool::new(true),
        }));
        {
            let mut st = self.lock();
            let Some(topic) = st.topics.get_mut(id) else {
                return;
            };
            if topic.destroyed {
                return;
            }
            topic.pending.push(peer.clone());
            topic.by_stream.push((mux.clone(), peer.clone()));
        }
        tokio::spawn(drive(self.clone(), *id, peer, channel));
    }

    fn on_pair(self: &Arc<Self>, mux: &Mux, request: PairRequest) {
        let Some(raw) = request.id.as_deref() else {
            return;
        };
        let Some(id) = <[u8; 32]>::try_from(raw).ok() else {
            (self.onwakeup)(raw, mux);
            return;
        };
        let known = {
            let st = self.lock();
            st.topics
                .get(&id)
                .is_some_and(|t| !t.sessions.is_empty() && !t.destroyed)
        };
        if known {
            self.open(&id, mux, false);
        } else {
            (self.onwakeup)(raw, mux);
        }
    }

    fn remove_stream(&self, mux: &Mux) {
        self.lock().muxers.retain(|m| !same_mux(m, mux));
    }

    fn remove_session(self: &Arc<Self>, id: &[u8; 32], session: &WakeupSession) -> Effect {
        let mut effect = Effect::default();
        let mut st = self.lock();
        let Some(topic) = st.topics.get_mut(id) else {
            return effect;
        };
        let before = topic.sessions.len();
        topic.sessions.retain(|s| !s.is_same(session));
        if topic.sessions.len() == before {
            return effect;
        }
        let active = topic.sessions.iter().any(|s| s.is_active());
        topic.set_active(active, &mut effect);
        self.check_gc(&mut st, id);
        effect
    }

    fn bump_activity(self: &Arc<Self>, id: &[u8; 32]) -> Effect {
        let mut effect = Effect::default();
        let mut st = self.lock();
        let Some(topic) = st.topics.get_mut(id) else {
            return effect;
        };
        let active = topic.sessions.iter().any(|s| s.is_active());
        topic.set_active(active, &mut effect);
        self.check_gc(&mut st, id);
        effect
    }

    fn add_peer(self: &Arc<Self>, id: &[u8; 32], peer: &WakeupPeer, open: &Handshake) -> Effect {
        let mut effect = Effect::default();
        let mut st = self.lock();
        let Some(topic) = st.topics.get_mut(id) else {
            return effect;
        };
        let info = peer.stream().stream_info();
        let Some(handshake_hash) = info.handshake_hash else {
            peer.close();
            return effect;
        };
        let ns = if info.is_initiator { 1 } else { 0 };
        if open.capability != capability(ns, &topic.capability, &handshake_hash) {
            peer.close();
            return effect;
        }
        topic.pending.retain(|p| !is_same_peer(p, peer));
        peer.set_pending(false);
        peer.set_active(open.active);
        topic.peers.push(peer.clone());
        if open.active {
            topic.active_peers += 1;
        }
        for session in topic.sessions.iter().rev() {
            effect
                .callbacks
                .push((session.clone(), Callback::PeerAdd(peer.clone())));
            if peer.is_active() {
                effect
                    .callbacks
                    .push((session.clone(), Callback::PeerActive(peer.clone())));
            }
        }
        self.check_gc(&mut st, id);
        effect
    }

    fn remove_peer(self: &Arc<Self>, id: &[u8; 32], peer: &WakeupPeer) -> Effect {
        let mut effect = Effect::default();
        let mut st = self.lock();
        let Some(topic) = st.topics.get_mut(id) else {
            return effect;
        };
        topic.by_stream.retain(|(m, _)| !same_mux(m, peer.stream()));
        if peer.is_pending() {
            topic.pending.retain(|p| !is_same_peer(p, peer));
            return effect;
        }
        let active = peer.is_active();
        if active {
            peer.set_active(false);
            topic.active_peers = topic.active_peers.saturating_sub(1);
        }
        topic.peers.retain(|p| !is_same_peer(p, peer));
        for session in topic.sessions.iter().rev() {
            if active {
                effect
                    .callbacks
                    .push((session.clone(), Callback::PeerInactive(peer.clone())));
            }
            effect
                .callbacks
                .push((session.clone(), Callback::PeerRemove(peer.clone())));
        }
        if active {
            self.check_gc(&mut st, id);
        }
        effect
    }

    fn on_info(self: &Arc<Self>, id: &[u8; 32], peer: &WakeupPeer, info: Info) -> Effect {
        let mut effect = Effect::default();
        let mut st = self.lock();
        let Some(topic) = st.topics.get_mut(id) else {
            return effect;
        };
        if info.active == peer.is_active() {
            return effect;
        }
        peer.set_active(info.active);
        if info.active {
            topic.active_peers += 1;
        } else {
            topic.active_peers = topic.active_peers.saturating_sub(1);
        }
        for session in topic.sessions.iter().rev() {
            let callback = if info.active {
                Callback::PeerActive(peer.clone())
            } else {
                Callback::PeerInactive(peer.clone())
            };
            effect.callbacks.push((session.clone(), callback));
        }
        self.check_gc(&mut st, id);
        effect
    }

    fn on_lookup(self: &Arc<Self>, id: &[u8; 32], peer: &WakeupPeer, req: Lookup) -> Effect {
        let mut effect = Effect::default();
        let st = self.lock();
        if let Some(topic) = st.topics.get(id) {
            for session in topic.sessions.iter().rev() {
                effect
                    .callbacks
                    .push((session.clone(), Callback::Lookup(req.clone(), peer.clone())));
            }
        }
        effect
    }

    fn on_announce(
        self: &Arc<Self>,
        id: &[u8; 32],
        peer: &WakeupPeer,
        writers: Announce,
    ) -> Effect {
        let mut effect = Effect::default();
        let writers: Arc<[Writer_]> = writers.into();
        let st = self.lock();
        if let Some(topic) = st.topics.get(id) {
            for session in topic.sessions.iter().rev() {
                effect.callbacks.push((
                    session.clone(),
                    Callback::Announce(writers.clone(), peer.clone()),
                ));
            }
        }
        effect
    }

    fn on_message(
        self: &Arc<Self>,
        id: &[u8; 32],
        peer: &WakeupPeer,
        kind: u64,
        data: compact_encoding::Bytes,
    ) -> Option<Effect> {
        let mut reader = compact_encoding::Reader::new(data);
        Some(match kind {
            LOOKUP => self.on_lookup(id, peer, Lookup::decode(&mut reader).ok()?),
            ANNOUNCE => self.on_announce(id, peer, Announce::decode(&mut reader).ok()?),
            INFO => self.on_info(id, peer, Info::decode(&mut reader).ok()?),
            _ => Effect::default(),
        })
    }

    fn check_gc(self: &Arc<Self>, st: &mut State, id: &[u8; 32]) {
        let Some(topic) = st.topics.get(id) else {
            return;
        };
        let should_gc = topic.active_peers == 0 && topic.sessions.is_empty();
        if should_gc && !topic.gcing {
            if let Some(topic) = st.topics.get_mut(id) {
                topic.gcing = true;
            }
            st.gc.push(*id);
        } else if !should_gc && topic.gcing {
            if let Some(topic) = st.topics.get_mut(id) {
                topic.gcing = false;
            }
            st.gc.retain(|gc| gc != id);
        }
        if st.gc.is_empty() {
            self.gc_wake.notify_one();
        } else if !self.gc_running.load(Ordering::Relaxed) {
            self.gc_running.store(true, Ordering::Relaxed);
            tokio::spawn(gc_loop(self.clone()));
        }
    }

    fn gc_tick(self: &Arc<Self>) {
        let mut effect = Effect::default();
        let mut doomed = Vec::new();
        {
            let mut st = self.lock();
            if st.gc.is_empty() {
                self.gc_running.store(false, Ordering::Relaxed);
                return;
            }
            for id in st.gc.clone() {
                if let Some(topic) = st.topics.get_mut(&id) {
                    topic.idle_ticks += 1;
                    if topic.idle_ticks >= GC_TICKS {
                        doomed.push(id);
                    }
                }
            }
            for id in doomed {
                self.teardown_locked(&mut st, &id, &mut effect);
            }
        }
        self.apply(None, effect);
    }

    fn teardown_locked(self: &Arc<Self>, st: &mut State, id: &[u8; 32], effect: &mut Effect) {
        let Some(topic) = st.topics.remove(id) else {
            return;
        };
        for peer in topic.peers.iter().chain(topic.pending.iter()) {
            peer.close();
        }
        st.gc.retain(|gc| gc != id);
        // JS runs the destroy handlers in reverse session order, like the others.
        for session in topic.sessions.into_iter().rev() {
            effect.callbacks.push((session, Callback::Destroy));
        }
        if st.gc.is_empty() {
            self.gc_wake.notify_one();
        }
    }
}

/// One tick of the JS GC interval per call; exits as soon as no topic waits.
async fn gc_loop(inner: Arc<Inner>) {
    loop {
        let notified = inner.gc_wake.notified();
        {
            let st = inner.lock();
            if st.gc.is_empty() {
                inner.gc_running.store(false, Ordering::Relaxed);
                return;
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(inner.gc_tick) => {}
            _ = notified => continue,
        }
        inner.gc_tick();
    }
}

async fn drive(inner: Arc<Inner>, id: [u8; 32], peer: WakeupPeer, mut channel: Channel) {
    match channel.opened().await {
        Some(handshake) => match compact_encoding::decode::<Handshake>(handshake) {
            Ok(open) => {
                let effect = inner.add_peer(&id, &peer, &open);
                inner.apply(Some(&id), effect);
            }
            Err(_) => channel.close(),
        },
        None => {
            let effect = inner.remove_peer(&id, &peer);
            inner.apply(Some(&id), effect);
            return;
        }
    }
    loop {
        match channel.recv().await {
            Some(Event::Message(message)) => {
                match inner.on_message(&id, &peer, message.kind, message.data) {
                    Some(effect) => inner.apply(Some(&id), effect),
                    None => {
                        channel.close();
                        break;
                    }
                }
            }
            Some(Event::Opened { .. }) => {}
            Some(Event::Closed { .. }) | None => break,
        }
    }
    let effect = inner.remove_peer(&id, &peer);
    inner.apply(Some(&id), effect);
}

/// `hypercore-crypto` `namespace('wakeup', 2)[index]`.
fn ns(index: usize) -> [u8; 32] {
    static NS: std::sync::LazyLock<Vec<[u8; 32]>> =
        std::sync::LazyLock::new(|| crypto::namespace(b"wakeup", 2));
    NS[index]
}

/// `crypto.hash([namespace, capability, handshakeHash])`.
fn capability(ns_index: usize, capability: &[u8; 32], handshake_hash: &[u8]) -> [u8; 32] {
    crypto::hash(&[&ns(ns_index), capability, handshake_hash])
}

fn same_mux(a: &Mux, b: &Mux) -> bool {
    // `Mux` exposes no id; its shared state's address identifies the stream.
    std::ptr::eq(a.stream_info(), b.stream_info())
}

fn is_same_peer(a: &WakeupPeer, b: &WakeupPeer) -> bool {
    Arc::ptr_eq(&a.0, &b.0)
}
