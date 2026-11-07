// HyperDHT testnet + npm protomux-wakeup peer for tests/interop.rs.
//
// node peer.js testnet
//   runs a 3-node local testnet, prints "bootstrap <port>", exits on stdin end.
// node peer.js peer <bootstrap-port> <capability-hex> [discovery-key-hex]
//   joins the topic, prints events, and runs commands from stdin:
//   announce <key-hex>:<length>[,...], lookup <hash-hex|none>, active,
//   inactive, state, close, quit.
const createTestnet = require('hyperdht/testnet')
const Hyperswarm = require('hyperswarm')
const WakeupSwarm = require('protomux-wakeup')
const crypto = require('hypercore-crypto')
const readline = require('readline')

const log = (s) => process.stdout.write(s + '\n')
const [mode, ...args] = process.argv.slice(2)
const hex = (b) => (b ? b.toString('hex') : 'none')
const writers = (spec) => spec.split(',').map((entry) => {
  const [key, length] = entry.split(':')
  return { key: Buffer.from(key, 'hex'), length: Number(length) }
})
const fmt = (list) => list.map(({ key, length }) => key.toString('hex') + ':' + length).join(',')

// Sent back for every lookup, like autobee-wakeup answers with its writers.
const ANSWER = [{ key: Buffer.alloc(32, 0x5a), length: 3 }]

async function testnet() {
  const t = await createTestnet(3, { host: '127.0.0.1' })
  log('bootstrap ' + t.bootstrap[0].port)
  process.stdin.resume()
  process.stdin.on('end', () => process.exit(0))
}

async function peer() {
  const [port, capHex, dkHex] = args
  const capability = Buffer.from(capHex, 'hex')
  const discoveryKey = dkHex ? Buffer.from(dkHex, 'hex') : crypto.discoveryKey(capability)

  const swarm = new Hyperswarm({ bootstrap: [{ host: '127.0.0.1', port: Number(port) }] })
  const wakeup = new WakeupSwarm((id) => log('wakeup ' + id.toString('hex')))
  let peer = null
  const session = wakeup.session(capability, {
    discoveryKey,
    onpeeradd(p) {
      peer = p
      log('peer-add')
    },
    onpeerremove() { log('peer-remove') },
    onpeeractive() { log('peer-active') },
    onpeerinactive() { log('peer-inactive') },
    onlookup(req, peer, session) {
      log('lookup ' + hex(req.hash))
      session.announce(peer, ANSWER)
      log('answered-lookup')
    },
    onannounce(list) { log('announce ' + fmt(list)) },
    ondestroy() { log('destroy') }
  })

  swarm.on('connection', (conn) => {
    log('connection')
    wakeup.addStream(conn)
  })
  await swarm.join(discoveryKey, { server: true, client: false }).flushed()
  log('joined')

  const topic = () => wakeup.topics.get(discoveryKey.toString('hex'))
  const lines = readline.createInterface({ input: process.stdin })
  for await (const line of lines) {
    const [cmd, arg] = line.trim().split(' ')
    if (cmd === 'announce') {
      session.announce(peer, writers(arg))
      log('sent-announce')
    } else if (cmd === 'lookup') {
      session.lookup(peer, { hash: arg === 'none' ? null : Buffer.from(arg, 'hex') })
      log('sent-lookup')
    } else if (cmd === 'broadcast') {
      session.broadcastLookup()
      log('sent-broadcast')
    } else if (cmd === 'active') {
      session.active()
      log('sent-active')
    } else if (cmd === 'inactive') {
      session.inactive()
      log('sent-inactive')
    } else if (cmd === 'state') {
      const t = topic()
      log('state peers=' + (t ? t.peers.length : 0) + ' pending=' + (t ? t.pendingPeers.length : 0))
    } else if (cmd === 'close') {
      await swarm.destroy()
      log('closed')
      process.exit(0)
    } else if (cmd === 'quit') {
      process.exit(0)
    }
  }
}

;({ testnet, peer })[mode]().catch((err) => {
  log('error ' + err.stack)
  process.exit(1)
})
