# protomux-wakeup-rs

[protomux-wakeup](https://github.com/holepunchto/protomux-wakeup) (2.9.0) for Rust: peers on the
`wakeup` Protomux protocol tell each other which writers they are missing, so an idle Autobee peer
is woken by the peer that has new data. Wire-compatible with npm, on [`protomux-rs`](../protomux-rs).

```rust,no_run
use protomux_wakeup::{Lookup, SessionHandlers, WakeupSwarm, wakeup::Writer_};

# async fn run(mux: protomux::Mux) {
let swarm = WakeupSwarm::new(|_topic_id, _mux| {}); // unknown topic: decline
let session = swarm.session([7; 32], SessionHandlers {
    on_lookup: Some(Box::new(|_req, peer, session| {
        let writers = vec![Writer_ { key: [7; 32], length: 42 }];
        session.announce(peer, &writers);
    })),
    ..Default::default()
});
swarm.add_stream(&mux);
session.broadcast_lookup(&Lookup { hash: None });
# }
```

- **Topic id** is `hypercore-crypto`'s discovery key of the capability (32 bytes), or
  `SessionHandlers::discovery_key`. Channels open under protocol `wakeup` with that id and a
  `handshake` proving the capability against the Noise handshake hash; a mismatch closes the
  channel on both ends before `on_peeradd`.
- **Messages**: `lookup` (optional hash), `announce` (array of `{key, length}` writers) and `info`
  (`active`), kinds 0/1/2. Handlers run in reverse session order as in JS, on the mux tasks, so they
  must not block; they may call back into their session. A malformed message closes its channel.
- **Activity**: `session.active()`/`inactive()` decide the per-topic `active` flag, which is sent in
  the handshake and in `info` messages whenever it flips. An active topic opens a channel on every
  registered stream; inactive topics keep their channels but new streams are not opened.
- **GC**: a topic with no sessions and no active peers is torn down after 5 ticks (default 2 s,
  `WakeupOptions::gc_tick_time`). The timer task exists only while at least one topic waits for GC.
  Teardown closes the channels and calls `on_destroy` for the sessions still registered; because
  GC only starts once the last session is gone, `on_destroy` normally fires from
  `WakeupSwarm::destroy()` with live sessions, as in JS.
- **Streams**: `add_stream(&Mux)` registers a mux for pairing and opens active topics on it. One
  `Mux` is one Noise stream, so a peer's `WakeupPeer::stream()` is the same handle consumers use
  for replica coupling. A mux without a Noise handshake hash cannot prove a capability and opens
  no channels. `has_stream(&Mux)` answers the JS `hasStream(stream)` case; the per-topic
  case is `session.has_stream(&Mux)`.

Not ported:

- `registerMetrics` and the `stats` counters: Prometheus is JS-only. Nothing on the wire changes.
- `WakeupPeer.userData`/`clock` and peer indices: Rust handles are `WakeupPeer` clones; attach your
  own state in the handler closure.
- `getMuxer`/`noiseStream` juggling: callers pass a `Mux`, normally
  `Mux::from_secret_stream(conn.peer.stream)`.
- The JS buffer/`userData`-keyed `peersByStream` reuse: a mux is matched by identity.

Behaviour a Rust `autobee` needs from `autobee-wakeup` (glue, no protocol): keep a session per
capability, announce every non-pending writer core (`key` + `length`), answer `onlookup` with the
current writer set, feed `onannounce` hints into the bee, and call `announce_by_stream` when a
coupler finds a stream that lacks one of its coupled cores. Core coupling itself (checking which
muxes already replicate a core) stays in the consumer; `core-coupler` has no wire behaviour.

## Tests

- `cargo test`: Rust peers over `protomux::memory::duplex` — handshake, announce, lookup (with and
  without a hash), active/inactive info, peer-remove on stream close, capability rejection and GC.
- `tests/interop.rs` (`-- --include-ignored`): npm `protomux-wakeup` on Hyperswarm against this
  crate on a peeroxide swarm, on a local HyperDHT testnet, both directions. Needs `npm install` in
  `tests/js`.

## License

MIT OR Apache-2.0
