import net, asyncnet, asyncdispatch, base64, nimSHA2, strutils, os, json, streams, macros, endians

import secrethandshake, crypto, libsodium/sodium
# local modules

proc fromString[T](str: string): T =
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
  DefaultPort* = 8008.Port

  ScuttlebuttKey = fromString[AuthKey](
    base64.decode "1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=")

  CipherHeaderLen = 2+crypto_secretbox_MACBYTES+crypto_secretbox_MACBYTES
  PlainHeaderLen = 2+16

type
  Request* = uint32

  PeerBase[SocketType] = ref object
    sock*: SocketType
    public*: SignPublicKey
    encKey, decKey: SecretBoxKey
    encHeaderNonce, encDataNonce, decNonce: SecretBoxNonce

  Peer* = PeerBase[Socket]
  AsyncPeer* = PeerBase[AsyncSocket]

proc newPeer*(sock: Socket): Peer = Peer(sock : sock)
proc newAsyncPeer*(sock: Asyncsocket): AsyncPeer = AsyncPeer(sock : sock)

proc init(peer: Peer | AsyncPeer, ourPublic: SignPublicKey, h: Handshake) =
  ## Initialize the asymetric encrypted channels and RPC tables
  peer.public = h.permPublic

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

  peer.decKey = boxKey(secret, ourPublic)
  peer.decNonce = boxNonce h.localAppMac

proc id*(peer: Peer | AsyncPeer): FeedId =
  FeedId(kind: FeedEd25519, key: peer.public)

proc accept*(peer: Peer | AsyncPeer,
             pair: SignPair) {.multisync.} =
  let shake = await secrethandshake.accept(
    peer.sock, pair, ScuttlebuttKey)
  peer.init(pair.pub, shake)
  # TODO zero the handshake keys

proc connect*(peer: Peer | AsyncPeer,
              pair: SignPair,
              key: SignPublicKey) {.multisync.} =
  let shake = await secrethandshake.connect(
    peer.sock, pair, key, ScuttlebuttKey)
  peer.init(pair.pub, shake)
  # TODO zero the handshake keys

proc send(p: Peer | AsyncPeer, data: string, chunkSize=4096) {.multisync.} =
  ## encrypt and send a packet.
  assert(p != nil)
  assert(chunkSize <= 0xFFFF)

  var
    header = newString PlainHeaderLen

  for i in countup(low(data), high(data), chunkSize):
    # send data in 4K stream packets
    let
      chunk = data[i..i+chunkSize]
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
    await p.sock.send(packet)

proc recv(p: Peer | AsyncPeer, size: int): Future[string] {.multisync.} =
  ## Receive, decrypt, and return a packet.
  result = newStringOfCap size
  while result.len < size:
    let cipherHeader = await p.sock.recv(CipherHeaderLen)
    if cipherHeader.len == 0:
      close p.sock
      echo "peer closed connection"
      return
    if cipherHeader.len != CipherHeaderLen:
      close p.sock
      raise newException(SystemError, "bad header read, got "& $cipherHeader.len)
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
          echo "closing socket"
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

proc close*(p: Peer | AsyncPeer) =
  ## Close the socket in an authenticated manner and destroy keys.
  if not p.sock.isClosed:
    let
      finalHeader = newString 2+16
      finalCipher = crypto_secretbox_easy(
        finalHeader,
        p.encHeaderNonce,
        p.encKey
      )
    asyncCheck p.sock.send(finalCipher)
  close p.sock
  zeroOut p.decKey
  zeroOut p.encKey

#
# RPC marshalling dredged from callback hell.
#
# A binary RPC encoding is used, but it isn't very useful
# so every call has an inner JSON encoding.
#

#[
function encodePair (msg) {

  var head = new Buffer(9)
  var flags = 0
  var value = msg.value !== undefined ? msg.value : msg.end

  //final packet
  if(isString(msg) && msg === GOODBYE) {
    head.fill(0)
    return [head, null]
  }

  if(isString(value)) {
    flags = STRING
    value = new Buffer(value)
  }
  else if(isBuffer(value)) {
    flags = BUFFER
  }
  else {
    flags = OBJECT
    value = new Buffer(JSON.stringify(value))
  }

  // does this frame represent a msg, a req, or a stream?

  //end, stream

  flags = msg.stream << 3 | msg.end << 2 | flags

  head[0] = flags

  head.writeUInt32BE(value.length, 1)
  head.writeInt32BE(msg.req || 0, 5)

  return [head, value]
}

function decodeHead (bytes) {
  if(bytes.length != 9)
    throw new Error('expected header to be 9 bytes long')
  var flags = bytes[0]
  var length = bytes.readUInt32BE(1)
  var req = bytes.readInt32BE(5)

  return {
    req    : req,
    stream : !!(flags & 8),
    end    : !!(flags & 4),
    value  : null,
    length : length,
    type   : flags & 3
  }
}
]#

type
  Magic* = uint8
const
    Buffer = 0x0.Magic
    String* = 0x1.Magic
    Object* = 0x2.Magic
    Stream* = 0x8.Magic
    End* = 0x4.Magic

proc send*(peer: Peer | AsyncPeer,
          req: Request,
          call: string,
          callFlags: Magic = 0) {.multisync.} =
  var
    magic = newStringOfCap(9+call.len)
  magic.setLen(9)
  magic.add(call)
  assert(magic.len < 4096)
  var
    callLen = magic.len.uint32 - 9
    request = req
  magic[0] = char(callFlags or Object)
  bigEndian32(addr magic[1], addr callLen)
  bigEndian32(addr magic[5], addr request)
  await peer.send(magic)

proc recvRaw*(peer: Peer | AsyncPeer):
            Future[(Request,string)] {.multisync.} =
  var
    magic = await peer.recv(9)
    callLen: uint
    callReq: Request
  assert(magic.len == 9)
  bigEndian32(addr callLen, addr magic[1])
  bigEndian32(addr callReq, addr magic[5])
  result[0] = Request(callReq.int * -1)
  result[1] = await peer.recv(callLen.int)

proc recv*(peer: Peer | AsyncPeer):
         Future[(Magic, Request, string)] {.multisync.} =
  var
    magic = await peer.recv(9)
    callLen: uint
    callReq: Request
  if magic == "":
    result = (0.Magic, 0.Request, "")
  else:
    bigEndian32(addr callLen, addr magic[1])
    bigEndian32(addr callReq, addr magic[5])
    if magic[0] != 0x0A.char:
      echo "req is ", callReq, ", magic is ", toHex magic[0], ", length is ",callLen
    result = (magic[0].Magic, Request(callReq.int * -1), await peer.recv(callLen.int))

    #[
    try:
      let jsNode = parseJson(data)
      result[1] = jsNode
      case jsNode.kind:
      of JObject:
        if jsNode.hasKey("name") and jsNode.hasKey("stack"):
          raise newException(Exception, jsNode["stack"].str)
      else:
        discard
    except JsonParsingError:
      echo "peer sent bad OBJECT"
    ]#

proc createHistoryStream*(peer: AsyncPeer,
                          req: Request,
                          id: FeedId, num=1) {.async.} =
  let call = %* {
    "name": ["createHistoryStream"],
    "args": [{"id":id, "seq":num, "live":true, "keys":true}],
    "type": "source"
  }
  await peer.send(req, $call, 0x0a.Magic)

proc blobsCreateWants*(peer: AsyncPeer,
                       req: Request) {.async.} =
  let call = %* {
    "name": ["blobs","createWants"],
    "args": [],
    "type": "source"
  }
  await peer.send(req, $call, 0x0a.Magic)

proc blobsGet*(peer: AsyncPeer, req: Request, blobId: string) {.async.} =
  let call = %* {
    "name":["blobs","get"],
    "args":[blobId],
    "type":"source"
  }
  await peer.send(req, $call, 0x0a.Magic)

proc blobsHas*(peer: AsyncPeer, req: Request, blobId: string) {.async.} =
  let call = %* {
    "name":["blobs","has"],
    "args":[blobId]
  }
  await peer.send(req, $call, 0x02.Magic)
