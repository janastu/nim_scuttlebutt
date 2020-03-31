import std/json, std/times

import net, asyncnet, asyncdispatch, base64, nimSHA2, strutils, os, streams, macros, tables, endians
import libsodium/sodium

import secrethandshake, stringify

import crypto

export SignPublicKey, BoxPublicKey, Port

proc parseSecretFile(): JsonNode =
  let
    path = getHomeDir() & ".ssb/secret"
    stream = newFileStream(path)

  if isNil(stream):
    raise newException(IOError, "cannot read secret from file " & path)
  defer: stream.close()

  var
    data = ""
    line = ""
  while readLine(stream, line):
    let chunks = split(line, '#', 1)
    if chunks.len >= 1:
      data.add(chunks[0])
  parseJson data

type

  Request* = uint32

  RpcStreamHandler* = proc (msg: JsonNode)

  SbotClientBase[PeerType] = ref object
    pair*: SignPair
    peer: PeerType
    requests: Table[Request, Future[JsonNode]]
    streams: Table[Request, RpcStreamHandler]
    currRequest: Request

  SbotClient* = SbotClientBase[Peer]
  AsyncSbotClient* = SbotClientBase[AsyncPeer]

proc newSbotClient*(pair: SignPair): SbotClient =
  new result
  result.pair = pair
  result.peer = newPeer(pair.pub, newSocket())
  result.requests = initTable[Request, Future[JsonNode]](16)
  result.streams = initTable[Request, RpcStreamHandler](16)

proc newAsyncSbotClient*(pair: SignPair): AsyncSbotClient =
  new result
  result.pair = pair
  result.peer = newAsyncPeer(pair.pub, newAsyncSocket())
  result.requests = initTable[Request, Future[JsonNode]](16)
  result.streams = initTable[Request, RpcStreamHandler](16)

proc newSbotClient*(): SbotClient =
  let secrets = parseSecretFile()
  var
    pubStr = secrets["public"].str
    secStr = secrets["private"].str
  pubStr.removeSuffix(".ed25519")
  secStr.removeSuffix(".ed25519")
  let
    pub = fromString[SignPublicKey](base64.decode pubStr)
    sec = fromString[SignSecretKey](base64.decode secStr)
  newSbotClient((pub,sec))

proc nextRequest(sbot: SbotClient | AsyncSbotClient): Request =
  inc sbot.currRequest
  sbot.currRequest

proc connect*(sbot: SbotClient | AsyncSbotClient,
              address = "localhost",
              port = DefaultPort) {.multisync.} =
  await connect(sbot.peer, sbot.pair, address, port, sbot.pair.pub)

proc close*(sbot: SbotClient | AsyncSbotClient) {.multisync.} =
  await close(sbot.peer)

proc feedId*(sbot: SbotClient | AsyncSbotClient): FeedId =
  FeedId(kind: FeedEd25519, key: sbot.pair[0])

proc secretBoxKey*(sbot: SbotClient | AsyncSbotClient): BoxSecretKey =
  crypto_sign_ed25519_sk_to_curve25519(sbot.pair.sec)
proc publicBoxKey*(sbot: SbotClient | AsyncSbotClient): BoxPublicKey =
  crypto_sign_ed25519_pk_to_curve25519(sbot.pair.pub)

const
  Buffer* = 0
  String* = 1
  Object* = 2
  Stream* = 1 shl 3
  End* = 1 shl 2

proc hasRequest(client: SbotClient | AsyncSbotClient, req: Request): bool =
  client.requests.hasKey(req) or client.streams.hasKey(req)

proc send(sbot: SbotClient | AsyncSbotClient,
          call: string,
          callFlags: uint8): Future[Request] {.multisync.} =

  var
    magic = newStringOfCap(9+call.len)
  magic.setLen(9)
  magic.add(call)
  assert(magic.len < 4096)
  var
    callLen = magic.len.uint32 - 9
    request = sbot.nextRequest
  magic[0] = char(callFlags or Object)
  bigEndian32(addr magic[1], addr callLen)
  bigEndian32(addr magic[5], addr request)
  await sbot.peer.send(magic[0..8])
  await sbot.peer.send(magic[9..high(magic)])
  result = request

proc send(sbot: SbotClient | AsyncSbotClient,
          obj: JsonNode,
          callFlags: uint8): Future[Request] {.multisync.} =

  var
    magic = newString(9)
  magic.add($obj)
  assert(magic.len < 4096)
  var
    callLen = magic.len.uint32 - 9
    request = sbot.nextRequest
  magic[0] = char(callFlags or Object)
  bigEndian32(addr magic[1], addr callLen)
  bigEndian32(addr magic[5], addr request)
  await sbot.peer.send(magic)
  result = request

proc recvRaw(sbot: SbotClient | AsyncSbotClient):
            Future[(Request,string)] {.multisync.} =
  var
    magic = await sbot.peer.recv(9)
    callLen: uint
    callReq: Request
  assert(magic.len == 9)
  bigEndian32(addr callLen, addr magic[1])
  bigEndian32(addr callReq, addr magic[5])
  result[0] = Request(callReq.int * -1)
  result[1] = await sbot.peer.recv(callLen.int)

proc recv(sbot: SbotClient | AsyncSbotClient):
         Future[(Request,JsonNode)] {.multisync.} =
  var
    magic = await sbot.peer.recv(9)
    callLen: uint
    callReq: Request
  assert(magic.len == 9)
  bigEndian32(addr callLen, addr magic[1])
  bigEndian32(addr callReq, addr magic[5])
  result[0] = Request(callReq.int * -1)

  let data = await sbot.peer.recv(callLen.int)
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

proc dispatch(client: SbotClient| AsyncSbotClient) {.multisync.} =
  var
    magic = await client.peer.recv(9)
    callLen: uint
    callReq: Request
    jsNode: JsonNode
  assert(magic.len == 9)
  bigEndian32(addr callLen, addr magic[1])
  bigEndian32(addr callReq, addr magic[5])
  callReq = Request(callReq.int * -1)

  let data = await client.peer.recv(callLen.int)

  if (magic[0].uint8 and OBJECT.uint8) != OBJECT:
    echo "don't know what to do with ", data
  else:
    try:
      jsNode = parseJson(data)
    except JsonParsingError:
      echo "peer sent bad OBJECT"
      return

    case jsNode.kind:
    of JObject:
      if client.streams.hasKey(callReq):
        if jsNode.hasKey("name"):
          client.streams.del(callReq)
        else:
          client.streams[callReq](jsNode)

      elif client.requests.hasKey(callReq):
        if jsNode.hasKey("name"):
          let err = newException(Exception, $jsNode["stack"])
          client.requests[callReq].fail(err)
          client.requests.del(callReq)
        else:
          client.requests[callReq].complete(jsNode)
          client.requests.del(callReq)
      else:
        const
          errResp = $ %*{ "message":"nope", "name":"Error", "stack":"Error: yes" }
        var
          errRespLen = errResp.len
        magic.setLen(9)
        magic[0] = 0x0e.char
        bigEndian32(addr magic[1], addr errRespLen)
        bigEndian32(addr magic[5], addr callReq)
        # set the reversed call id

        await client.peer.send(magic)
        await client.peer.send(errResp)

    else:
      discard

proc sendRpc*(sbot: SbotClient | AsyncSbotClient,
              callName: string,
              callArgs: JsonNode,
              callFlags: uint8): Future[JsonNode] {.multisync.} =
  let
    call = %* { "name": [ callName ], "args": callArgs }
    callReq = await sbot.send(call, callFlags)
  while true:
    let
      resp = await sbot.recv()
    if resp[0] == callReq:
      result = resp[1]
      break

proc sendRpc*(sbot: SbotClient | AsyncSbotClient,
              callNames: seq[string],
              callArgs: JsonNode,
              callFlags: uint8): Future[JsonNode] {.multisync.} =
  let
    call = %* { "name": callNames, "args": callArgs }
    callReq = await sbot.send(call, callFlags)
  while true:
    let
      resp = await sbot.recv()
    if resp[0] == callReq:
      result = resp[1]
      break

proc sendRpcSource*(sbot: SbotClient | AsyncSbotClient,
                    callName: string,
                    callArgs: JsonNode,
                    callFlags: uint8): Future[JsonNode] {.multisync.} =
  let
    call = %* { "name": [callName], "args": callArgs, "type": "source" }
    callReq = await sbot.send(call, callFlags)
  while true:
    let
      resp = await sbot.recv()
    if resp[0] == callReq:
      result = resp[1]
      break

proc initiateRpcStream*(sbot: SbotClient | AsyncSbotClient,
                        callName: string,
                        callArgs: JsonNode,
                        callFlags: uint8,
                        callHandler: RpcStreamHandler):
                       Future[Request] {.multisync.} =
  let
    call = %* { "name": [callName], "args": callArgs, "type": "source" }
    callReq = await sbot.send(call, callFlags)
  sbot.streams[callReq] = callHandler
  result = callReq

proc closeRpcStream*(client: SbotClient, req: Request) =
  client.streams.del(req)

proc whoami*(sbot: SbotClient | AsyncSbotClient): Future[string] {.multisync.} =
  ## Get Scuttlebot identity
  let msg = await sbot.sendRpc("whoami", %*[], 0)
  result = msg["id"].str

proc getLatest*(sbot: SbotClient | AsyncSbotClient):
               Future[JsonNode] {.multisync} =
  ## Get the last message on the local feed
  result = await sbot.sendRpc("getLatest", %[$sbot.feedId], 0)

proc getLatest*(sbot: SbotClient | AsyncSbotClient, feedId: FeedId):
               Future[JsonNode] {.multisync} =
  ## Get the last message on an arbitrary feed
  result = await sbot.sendRpc("getLatest", %[$feedId], 0)

proc get*(sbot: SbotClient | AsyncSbotClient, msgid: string):
         Future[JsonNode] {.multisync} =
  result = await sbot.sendRpc("get", %[msgid], 0)

iterator feedMessages*(sbot: SbotClient, feedId: FeedId): (string, JsonNode) =
  ## Iterate thru a feed starting from the latest message.
  let
    latest = sbot.getLatest(feedId)
  if latest.kind == JObject:
    var
      id = latest["key"].str
      msg = latest["value"]
    while true:
      yield (id, msg)
      if msg["previous"].kind != JString:
        break
      id = msg["previous"].str
      msg = sbot.get(id)

type
  BlobKind* = enum
    BlobSHA256

  BlobId* = ref BlobIdObj
  BlobIdObj = object
    case kind*: BlobKind
    of BlobSHA256: digest*: SHA256Digest

const
  BlobSuffix = ".sha256"

proc `$`*(b: BlobId): string =
  assert(b.kind == BlobSHA256)
  "&"& base64.encode(b.digest)& BlobSuffix

proc `%`*(b: BlobId): JsonNode =
  newJString $b

proc parseBlobId*(str: string): BlobId =
  if str[0] == '&' and str.endsWith(BlobSuffix):
    let bin = base64.decode str[1..str.high-BlobSuffix.len]
    result = BlobId(kind: BlobSHA256, digest: fromString[SHA256Digest](bin))
  else:
    raise newException(
      ValueError, "invalid or unhandled blob digest string '$#'" % str)

proc blobId*(data: string): BlobId =
  BlobId(kind: BlobSHA256, digest: computeSHA256(data))


proc addBlob*(sbot: SbotClient | AsyncSbotClient, blob: string): Future[BlobId] {.multisync.} =
  ## Add a blob to the sbot blob store and return its identifier.
  const maxTransferSize = 0xffff
  assert(blob.len <= uint32.high.int)

  const call = $(%* {"name":["blobs","add"],"args":[],"type":"sink"})
  var
    callReq = await sbot.send(call, 0x0a)
    magic = newString(9)
    blobLen: uint32
  bigEndian32(addr magic[5], addr callReq)

  magic[0] = 0x08.char
  for i in countup(blob.low, blob.high, maxTransferSize):
    blobLen = min(uint32(blob.len - i), maxTransferSize)
    bigEndian32(addr magic[1], addr blobLen)
    await sbot.peer.send(magic)
    await sbot.peer.send(blob[i..i+int(blobLen)-1], 0xFFFF)

  const End = "true"
  var endLen = End.len
  magic[0] = 0x0e.char
  bigEndian32(addr magic[1], addr endLen)
  bigEndian32(addr magic[5], addr callReq)
  await sbot.peer.send(magic)
  await sbot.peer.send(End)

  while true:
    let
      resp = await sbot.recv()
    if resp[0] == callReq:
      let js = resp[1]
      if js.kind == JBool and js.bval == true:
        result = BlobId(kind: BlobSHA256, digest: computeSHA256(blob))
      break

proc wantBlob*(sbot: SbotClient | AsyncSbotClient, blobId: string): Future[bool] {.multisync.} =
  let js = await sbot.sendRpc(@["blobs", "want"], %*[ blobId ], 0)
  result = js.bval

proc getBlob*(sbot: SbotClient | AsyncSbotClient, blobId: string):
             Future[string] {.multisync.} =
  ## Retrieve a blob by id. Blobs may be up to 2MB in size
  let
    call = $(%* {"name":["blobs","get"],"args":[blobId],"type":"source"})

  var
    callReq = await sbot.send(call, 0x0a)
    blob = ""

  while true:
    let resp = await sbot.recvRaw()
    if resp[0] == callReq:
      if blob != "" and resp[1] == "true":
        break
      blob.add(resp[1])
  result = blob

proc sign*(sbot: SbotClient | AsyncSbotClient, obj: var JsonNode) =
  ## Sign a JSON object.
  sign(obj, sbot.pair.sec)

proc send*(sbot: SbotClient; content: JsonNode): JsonNode =
  ## Send a message.
  let
    previous = sbot.getLatest()
    timestamp = max(
      previous["value"]["timestamp"].num + 1,
      epochTime().BiggestInt)
  var
    jsPost = %*
      { "previous": previous["key"]
      , "author": previous["value"]["author"]
      , "sequence": previous["value"]["sequence"].num + 1
      , "timestamp": timestamp
      , "hash": "sha256"
      , "content": content
      }
  sign(jsPost, sbot.pair.sec)
  sbot.sendRpc("add", %[jsPost], 0)

when isMainModule:
  import unittest, times

  suite "Sbot client":
    let
      sbot = newSbotClient()
    sbot.connect()

    test "verify feed":
      let
        latest = sbot.getLatest()
      let
        msg = latest["value"]

      assert(verify(msg, sbot.pair.pub))

    test "blobs":
      for i in 1..32:
        let
          input = newString i
          blobId = sbot.addBlob(input)
          output = sbot.getBlob($blobId)
        assert(output == input)

    test "multibox/multiunbox":
      let
        sec = crypto_sign_ed25519_sk_to_curve25519(sbot.pair.sec)
        pub = crypto_sign_ed25519_pk_to_curve25519(sbot.pair.pub)
        msg = "hello world!"
        cipher = multibox(msg, @[pub])
        plain = multiboxOpen(cipher, sec)
      assert(plain == msg)

    test "decrypt feed":
      let
        sec = crypto_sign_ed25519_sk_to_curve25519(sbot.pair.sec)
        latest = sbot.getLatest()
      var
        msg = latest["value"]
      while msg["sequence"].num > 1:
        let
          content = msg["content"]
        if content.kind == JString:
          if content.str.endsWith(".box"):
            let
              cipher = base64.decode content.str[0..high(content.str)-4]
              plain = multiboxOpen(cipher, sec)
            assert(plain != nil)
        msg = sbot.get(msg["previous"].str)

      sbot.close()
