# /home/repo/ssbc/scuttlebot/node_modules/pull-box-stream/index.js

import net, asyncnet, asyncdispatch, base64, nimSHA2, strutils, endians
import libsodium/sodium

proc fromString*[T](str: string): T =
  for i in low(result)..high(result):
    result[i] = str[i]

proc zeroOut[I](a: var array[I, char]) =
   for i in low(a)..high(a): a[i] = '\0'

proc isZeroed(s: string): bool =
  for i in low(s)..high(s):
    if s[i] != '\0': return false
  true

proc inc(a: var SecretBoxNonce) =
  ## increment a nonce buffer as though it was a uint24
  while true:
    for i in countdown(high(a), low(a)):
      if a[i] < high char:
        a[i] = (a[i].uint8+1).char
        return
      else:
        a[i] = low char

const
  AppKey = base64.decode "1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s="
  appKey = fromString[AuthKey](AppKey)

  ChallengeLength = 64
  ClientAuthLength = 16+32+64
  ServerAuthLength = 16+64

  CipherHeaderLen = 2+crypto_secretbox_MACBYTES+crypto_secretbox_MACBYTES
  PlainHeaderLen = 2+16

  DefaultPort* = Port(8008)

type SecretHandshakeError* = object of CatchableError

proc raiseSH(err: string) =
  raise newException(SecretHandshakeError, err)

type
  Node* = ref object
    pair: SignPair
    bcastSock: Socket
    ipAddr: (string, Port)

proc newNode*(app: AuthKey,
              seed: SignSeed,
              ipAddr: (string, Port)): Node =
  result = Node(
    pair : crypto_sign_seed_keypair(seed),
    ipAddr : ipAddr,
    bcastSock : newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, false)
  )
  result.bcastSock.bindAddr(ipAddr[1], $ipAddr[0])
  result.bcastSock.setSockOpt(OptBroadcast, true)

proc announce*(node: Node) =
  let
    sock = node.bcastSock
    addrPort = getLocalAddr(sock)
  var msg =
    "net:" & $addrPort[0] & ":" & $addrPort[1] &
    "~shs:" & base64.encode($node.pair.pub)
  sock.sendTo($IPv4_broadcast(), DefaultPort, msg)

type
  PeerBase*[SocketType] = ref object
    sock: SocketType
    public: SignPublicKey
    encKey, decKey: SecretBoxKey
    encHeaderNonce, encDataNonce, decNonce: SecretBoxNonce

  Peer* = PeerBase[Socket]
  AsyncPeer* = PeerBase[AsyncSocket]

proc newPeer*(key: SignPublicKey, sock: Socket): Peer =
  Peer(sock : sock, public: key)

proc newAsyncPeer*(sock: Asyncsocket): AsyncPeer =
  AsyncPeer(sock : sock)

proc newAsyncPeer*(key: SignPublicKey, sock: Asyncsocket): AsyncPeer =
  AsyncPeer(sock : sock, public: key)

proc send*(p: Peer | AsyncPeer, data: string, chunkSize=4096) {.multisync.} =
  ## encrypt and send a packet
  assert(p != nil)
  assert(chunkSize <= 0xFFFF)

  var
    header = newString PlainHeaderLen

  for i in countup(low(data), high(data), chunkSize):
    # send data in 4K stream packets
    let
      chunk = data[i..min(data.high, i+chunkSize)]
    var
      chunkLen = chunk.len
      cipherAndMac = crypto_secretbox_detached(p.encKey, p.encDataNonce, chunk)
    inc p.encDataNonce
    inc p.encDataNonce

    bigEndian16(addr header[0], addr chunkLen)
    copymem(addr header[2], addr cipherAndMac[1], 16)

    let cipherHeader = crypto_secretbox_easy(header, p.encHeaderNonce, p.encKey)
    inc p.encHeaderNonce
    inc p.encHeaderNonce

    let packet = cipherHeader & cipherAndMac[0]
    echo "send ", packet.len, " byte packet"
    await p.sock.send(packet)

proc recv*(p: Peer | AsyncPeer, size: int): Future[string] {.multisync.} =
  ## receive, decrypt, and return a packet
  result = newStringOfCap size
  while result.len < size:
    let cipherHeader = await p.sock.recv(CipherHeaderLen)
    if cipherHeader.len == 0:
      close p.sock
      raise newException(IOError, "peer closed connection")
    if cipherHeader.len != CipherHeaderLen:
      close p.sock
      raise newException(IOError, "bad header read, got " & $cipherHeader.len)
    else:
      var plainHeader = crypto_secretbox_open_easy(
        cipherHeader,
        p.decNonce,
        p.decKey
      )
      if plainHeader.len == PlainHeaderLen:
        if plainHeader.isZeroed:
          zeroOut p.decKey
          zeroOut p.encKey
          close p.sock
          return
        else:
          inc p.decNonce

          var
            msgLen: uint
          bigEndian16(addr msgLen, addr plainHeader[0])
          let
            cipher = await p.sock.recv(msgLen.int)
            mac = fromString[SecretBoxMac](plainHeader[2..high(plainHeader)])
            plain = crypto_secretbox_open_detached(
              p.decKey,
              p.decNonce,
              mac,
              cipher
            )
          inc p.decNonce
          result.add(plain)
  assert(result.len == size)

proc close*(p: Peer | AsyncPeer) {.multisync.} =
  ## Close the socket in an authenticated manner and destroy keys
  let
    finalHeader = newString 2+16
    finalCipher = crypto_secretbox_easy(
      finalHeader,
      p.encHeaderNonce,
      p.encKey
    )
  zeroOut p.decKey
  zeroOut p.encKey

  await p.sock.send(finalCipher)
  # let the other side close the socket

type

  Handshake = ptr HandshakeObj
  HandshakeObj = object
    permPair: SignPair
    tempPair: BoxPair
    localAppMac, remoteAppMac: AuthTag
    public: SignPublicKey # of the other side
    secret1: BoxSecretKey
    digest1: SHA256Digest
    secret2: SecretBoxKey
    digest2: SHA256Digest
    secret3: SecretBoxKey
    a_bob: array[32, char]
    b_alice: array[32, char]
    hello: string

proc newHandshake(perm: SignPair): HandshakeObj =
  HandshakeObj(
    permPair : perm,
    tempPair : crypto_box_keypair()
  )


proc createIOStreams(peer: Peer | AsyncPeer, h: Handshake) =
  ## Create the asymetric encrypted I/O channels
  proc boxKey(secret: SecretBoxKey, public: SignPublicKey): SecretBoxKey =
    computeSHA256($secret & $public)
  proc boxNonce(mac: AuthTag): SecretBoxNonce =
    for i in low(mac)..high(result): result[i] = mac[i]

  var secret = computeSHA256($h.secret3)

  peer.encKey = boxKey(secret, peer.public)
  peer.encHeaderNonce = boxNonce h.remoteAppMac
  peer.encDataNonce = peer.encHeaderNonce
  inc peer.encDataNonce
  # The data nonce is used before the header nonce, but lags by one

  peer.decKey = boxKey(secret, h.permPair.pub)
  peer.decNonce = boxNonce h.localAppMac

  zeroOut secret
  zeroOut h.secret3
  zeroOut h.secret1
  zeroOut h.permPair.sec
  zeroOut h.tempPair.sec
  # stack variables, but worth destroying

proc sendChallenge(peer: Peer | AsyncPeer, h: Handshake) {.multisync.} =
  h.localAppMac = crypto_auth($h.tempPair.pub, appKey)
  let challenge = $h.localAppMac & $h.tempPair.pub

  await send(peer.sock, challenge)

proc recvChallenge(peer: Peer | AsyncPeer, h: Handshake) {.multisync.} =
  let challenge = await recv(peer.sock, ChallengeLength)
  if (challenge.len == ChallengeLength):
    h.remoteAppMac = fromString[AuthTag](challenge[low(challenge)..31])
    h.public = fromString[SignPublicKey](challenge[32..high(challenge)])

    if crypto_auth_verify(h.remoteAppMac, $h.public, appKey):
      h.secret1 = crypto_scalarmult(h.tempPair.sec, h.public)
      h.digest1 = computeSHA256($h.secret1)
      return

  # close(peer.sock)
  raiseSH "phase 1 challenge failed verification"

proc accept*(pair: SignPair,
             sock: AsyncSocket): Future[AsyncPeer] {.async.} =
  result = newAsyncPeer(sock)
  let
    peer = result
  var
    handshake = newHandshake(pair)
    shake = addr handshake
    h = shake

  await recvChallenge(peer, shake)
  await sendChallenge(peer, shake)

  block recvClientAuth:
    let auth = await recv(peer.sock, ClientAuthLength)
    if auth.len == ClientAuthLength:
      let secKey = crypto_sign_ed25519_sk_to_curve25519(h.permPair.sec)
      h.a_bob = crypto_scalarmult(secKey, h.public)

      var sha = initSHA[SHA256]()
      sha.update($appKey)
      sha.update($h.secret1)
      sha.update($h.a_bob)
      h.digest2 = sha.final()
      var
        nonce: SecretBoxNonce

      h.hello = crypto_secretbox_open_easy(auth, nonce, h.digest2)
      let
        sig = fromString[SignDetached](h.hello[low(h.hello)..high(h.hello)])
        pub = fromString[SignPublicKey](h.hello[sig.len..high(h.hello)])
        msg = $appKey & $h.permPair.pub & $h.digest1
      if sodium.crypto_sign_verify_detached(sig, msg, pub):
        h.public = pub
        break recvClientAuth

      raise newException(IOError, "client authentication failed")

  block sendServerAccept:
    h.b_alice = crypto_scalarmult(h.tempPair.sec, crypto_sign_ed25519_pk_to_curve25519(h.public))
    var sha = initSHA[SHA256]()
    sha.update($appKey)
    sha.update($h.secret1)
    sha.update($h.a_bob)
    sha.update($h.b_alice)
    h.secret3 = sha.final()

    let
      msg = $appKey & h.hello & $h.digest1
      okay = crypto_sign_detached(msg, h.permPair.sec)
    var nonce: SecretBoxNonce
    let accept = crypto_secretbox_easy($okay, nonce, h.secret3)

    await send(peer.sock, accept)

  createIoStreams(peer, shake)

proc connect*(peer: Peer | AsyncPeer,
              pair: SignPair,
              address: string,
              port: Port,
              key: SignPublicKey) {.multisync.} =
  await peer.sock.connect(address, port)
  var
    handshake = newHandshake(pair)
    shake = addr handshake
    h = shake

  await sendChallenge(peer, shake)
  await recvChallenge(peer, shake)

  block sendClientAuth:
    let pubKey = crypto_sign_ed25519_pk_to_curve25519(peer.public)
    h.a_bob = crypto_scalarmult(h.tempPair.sec, pubKey)

    var sha = initSHA[SHA256]()
    sha.update($appKey)
    sha.update($h.secret1)
    sha.update($h.a_bob)
    h.digest2 = sha.final()

    let
      msg = $appKey & $peer.public & $h.digest1
      sig = crypto_sign_detached(msg, h.permPair.sec)
    h.hello = $sig & $h.permPair.pub

    var nonce: SecretBoxNonce
    # use a zeroed nonce
    let auth = crypto_secretbox_easy(h.hello, nonce, h.digest2)
    await send(peer.sock, auth)

  block recvServerAccept:
    let auth = await recv(peer.sock, ServerAuthLength)

    if auth.len == ServerAuthLength:
      let
        sk = crypto_sign_ed25519_sk_to_curve25519(h.permPair.sec)
      h.b_alice = crypto_scalarmult(sk, h.public)
      var sha = initSHA[SHA256]()
      sha.update($appKey)
      sha.update($h.secret1)
      sha.update($h.a_bob)
      sha.update($h.b_alice)
      h.secret3 = sha.final()

      var nonce: SecretBoxNonce
      let
        msg = $appKey & h.hello & $h.digest1
        plain = crypto_secretbox_open_easy(auth, nonce, h.secret3)

      if plain != "":
        let
          sig = fromString[SignDetached](plain)

        if crypto_sign_verify_detached(sig, msg, peer.public):
          break recvServerAccept

    raise newException(CatchableError, "server authentication failed")

  createIoStreams(peer, shake)

import json, tables

type
  RpcProc* = proc (peer: Peer, params: JsonNode): Future[JsonNode]

  RpcProcError* = ref object of Exception
    code*: int
    data*: JsonNode

type

  RpcTree = ref object
    nodes: ref Table[string, RpcTree]
    leafs: ref Table[string, RpcProc]

var rpcRoot = new(RpcTree)


proc registerRpc*(rpc: RpcProc, names: varargs[string]) =
  # {"name":["gossip","ping"],"args":[{"timeout":300000}],"type":"duplex"}
  var tree = rpcRoot
  for i in low(names)..high(names)-1:
    let name = names[i]
    if tree.nodes == nil:
      tree.nodes = { name: new(RpcTree) }.newTable
    elif not tree.nodes.contains(name):
      tree.nodes[name] = new(RpcTree)
    tree = tree.nodes[name]

  let name = names[high(names)]
  if tree.leafs == nil:
    tree.leafs = { name: rpc }.newTable
  else:
    tree.leafs[name] = rpc
