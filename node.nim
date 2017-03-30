import asyncnet, asyncdispatch, net, base64, random, json, tables, os, sets, strutils
# stdlib

import feedstore, blobstore, peer, crypto, libsodium/sodium, secrethandshake
# local modules

proc arrayFromString[I](arr: var array[I, char], str: string) =
  for i in low(arr)..high(arr):
    arr[i] = str[i]

proc fromString[T](str: string): T =
  for i in low(result)..high(result):
    result[i] = str[i]

const
  DefaultPort* = Port(8008)
  BlobsDir = "blobs/sha256"
  FeedsDir = "feeds/ed25519"

type
  Feed = ref object
    stream: FutureStream[string]
    log: LogFile

  Handler = proc(node: Node, peer: Peer, req: Request, js: JsonNode): Future[void]

  Peer = ref object
    ssb: peer.AsyncPeer
    streams: Table[Request, FutureStream[string]]
    handlers: TableRef[string, Handler]
    blobWantsReq: Request
    currRequest: Request

  Node* = ref object
    sock: AsyncSocket
    bcastSock: AsyncSocket
    pair: SignPair
    peers: seq[Peer]
    feedStore: FeedStore
    blobStore: BlobStore
    follows: Table[string, Feed]

proc newNodePeer(sock: AsyncSocket): Peer =
  Peer(
    ssb: peer.newAsyncPeer(sock),
    streams: initTable[Request, FutureStream[string]](),
    handlers: newTable[string, Handler](8))

proc nextRequest(peer: Peer | AsyncPeer): Request =
  inc peer.currRequest
  peer.currRequest

proc registerHandler(peer: Peer, name: string, handler: Handler) =
  peer.handlers[name] = handler



proc newNode*(seed: SignSeed, port = DefaultPort, address = ""): Node =
  new result
  result.pair = crypto_sign_seed_keypair(seed)
  result.sock = newAsyncSocket()
  result.sock.bindAddr(port, address)
  result.peers = newSeq[Peer]()
  result.feedStore = newFeedStore FeedsDir
  result.blobStore = newBlobStore BlobsDir
  result.follows = initTable[string, Feed]()

proc close*(node: Node) =
  close node.bcastSock
  for peer in node.peers.items():
    close peer.ssb
  node.peers.setLen(0)
  for feed in node.follows.values():
    complete feed.stream
    close feed.log
  clear node.follows
  close node.sock

proc feedId*(node: Node): FeedId =
  FeedId(kind: FeedEd25519, key: node.pair.pub)

proc announce*(node: Node) {.async.} =
  let
    sock = node.bcastSock
    addrPort = getLocalAddr(sock)
    msg =
      "net:" & $addrPort[0] & ":" & $addrPort[1] &
      "~shs:" & base64.encode(node.pair.pub, newLine="")
  if addrPort[0] == "0.0.0.0":
    echo "cannot announce our address as ",addrPort[0]
  else:
    echo "send ",msg
    discard sock.sendTo($IPv4_broadcast(), DefaultPort, msg)

proc newStream(peer: Peer): (Request, FutureStream[string]) =
  ## Allocate a new request id and associated FutureStream
  result[0] = peer.nextRequest
  result[1] = newFutureStream[string]("peer.newStream")
  peer.streams[result[0]] = result[1]

proc replicate(node: Node, peer: Peer, feed: Feed, feedId: string) {.async.}

proc follow(node: Node, id: FeedId) =
  if not node.follows.hasKey($id):
    let feed = Feed(
      stream: newFutureStream[string]("newFeed"),
      log: node.feedStore.get(id)
    )
    node.follows[$id] = feed
    for peer in node.peers.items:
      asyncCheck node.replicate(peer, feed, $id)

proc wantBlob(b: BlobId) =
  echo "found ", b

proc isBlob(s: string): bool =
  ## Check if a string is likely a blob reference
  # TODO support for multiple digest types
  (s[0] == '&' and s.len == 52 and s.endsWith("=.sha256"))

proc processBlobs(js: JsonNode) =
  ## Recursively find all blob references in a message
  try:
    case js.kind:
    of JString:
      if js.str.isBlob:
        wantBlob(parseBlobId js.str)

    of JObject:
      for key, val in js.getFields.pairs:
        if key.isBlob:
          wantBlob(parseBlobId key)
        processBlobs val

    of JArray:
      for elem in js.getElems.items:
        processBlobs elem
    else:
      discard
  except ValueError:
    discard "blob parsing failed"



#[
  if content.kind != JObect: return
  if not content.hasKey("mentions"): return
  let mentions = content["mentions"]
  if mentions.kind != JArray:
  for x in mentions.getElems:
            let link = x["link"].str
            if link[0] == '&':
              let blob = parseBlobId link
              assert(blob.kind == BlobSHA256)
              if node.blobs.contains(blob.digest):
                echo link," found in blob store"
              else:
                 let (blobReq, blobFut) = peer.newStream()
                 # register stream
                 echo "requesting blob ", link
                 await peer.emitWantBlob(link)
                 #[
                 await peer.ssb.blobsGet(blobReq, link)
                 let digest = await node.blobs.put(blobFut)
                 # the blob store will drain the stream as dispatch passes data to it
                 if digest != blob.digest:
                   echo "blob mismatch, want ", bin2hex(blob.digest), " got ", bin2hex(digest)
                 else:
                   echo " put to store as ", bin2hex(digest)
                   ]#
]#  

proc parseMessage(node: Node, content: JsonNode) =
  if content.kind != JObject: return
  if not content.hasKey("type"): return
  let typ = content["type"]
  if typ.kind != JString: return
  case typ.str:
  of "about":
    if content.hasKey("description"):
      echo content["description"].str
  else:
    discard
  processBlobs content

proc parseFollowedMessage(node: Node, content: JsonNode) =
  if content.kind != JObject: return
  if not content.hasKey("type"): return
  let typ = content["type"]
  if typ.kind != JString: return
  case typ.str:
  of "contact":
    let
      contact = content["contact"].str
      following = content["following"].bval
    if following:
      node.follow(parseFeedId contact)
  of "about":
    if content.hasKey("description"):
      echo content["description"].str
  else:
    echo "not processing ", typ.str
    discard
  processBlobs content

proc processFeed(node: Node, feed: Feed, feedId: FeedId) {.async.} =
  # TODO cache the last message at Feed
  var nextNum = await feed.log.height()
  inc nextNum
  while true:
    let
      (active, data) = await feed.stream.read()
    if not active: break
    let
      js = parseJson data
      jsVal = js["value"]
    block:
      let num = jsVal["sequence"].num.int
      if num == nextNum:
        #if not verify(jsVal, feedId):
        #  echo "failed to verify\n", js["key"].str
        if num > 1:
          let
            prevStr = await feed.log.get(num-1)
          var prevJs: JsonNode
          try:
            prevJs = parseJson prevStr
          except:
            echo "bad message on feed ", $feedId, "\n########\n", prevStr, "\n########"
            complete feed.stream
            break
          if js["value"]["previous"].str != prevJs["key"].str:
            echo "previous message mismatch, ",js["value"]["previous"].str," ",prevJs["key"].str
            quit -1
            break
        try:
          node.parseMessage(jsVal["content"])
        except:
          echo "failed to parseMessage ", jsVal["content"]
        await feed.log.append($js, num)
        # write message to log file
        inc nextNum

proc processFollowedFeed(node: Node, feed: Feed, feedId: FeedId) {.async.} =
  # TODO cache the last message at Feed
  var nextNum = await feed.log.height()
  inc nextNum
  while true:
    let
      (active, data) = await feed.stream.read()
    if not active: break
    let
      js = parseJson data
      jsVal = js["value"]
    block:
      let num = jsVal["sequence"].num.int
      if num == nextNum:
        #if not verify(jsVal, feedId):
        #  echo "failed to verify\n", js["key"].str
        if num > 1:
          let
            prevStr = await feed.log.get(num-1)
          var prevJs: JsonNode
          try:
            prevJs = parseJson prevStr
          except:
            echo "bad message on feed ", $feedId, "\n########\n", prevStr, "\n########"
            complete feed.stream
            break
          if js["value"]["previous"].str != prevJs["key"].str:
            echo "previous message mismatch, ",js["value"]["previous"].str," ",prevJs["key"].str
            quit -1
            break
        try:
          node.parseFollowedMessage(jsVal["content"])
        except:
          echo "failed to parseFollowedMessage ", jsVal["content"]
        await feed.log.append($js, num)
        # write message to log file
        inc nextNum
                 
#[

proc createHistoryStreamHandler(node: Node, peer: Peer,
                         req: Request, js: JsonNode) {.async.} =
  return
  let
    args = js["args"].elems[0]
    # dictionaries make great a element for your single item list
    feed = args["id"].str
  var num: int
  if args.hasKey("seq"):
    num = args["seq"].num.int
  let
    log = node.logFile(feed)
    height = await log.height
  while num <= height:
    await peer.ssb.send(req, await log.get(num))
    inc num
  # TODO keep sending messages
]#

proc emitWantBlob(peer: Peer, blobId: string) {.async.} =
  ## Inform a peer that we want a blob
  if peer.blobWantsReq == 0.Request:
    let (req, fut) = peer.newStream()
    discard fut
    await peer.ssb.blobsCreateWants(req)
    peer.blobWantsReq = req
  let msg = %* { blobId: -1 }
  await peer.ssb.send(
    peer.blobWantsReq,
    $msg,
    0x0a.Magic)
  
proc replicate(node: Node, peer: Peer, feed: Feed, feedId: string) {.async.} =
  ## Request the peers log and write it to file
  let feedId = parseFeedId feedId
  # TODO: just use FeedId everywhere
  let
    req = peer.nextRequest
    height = await feed.log.height
  peer.streams[req] = feed.stream
  await peer.ssb.createHistoryStream(req, feedId, height)

  #[
  while not feed.stream.finished:
    
    let
      (active, data) = await histFut.read()
    if not active or data.isNil: break
    let
      js = parseJson data
      jsVal = js["value"]
    block:
      inc height
      let num = jsVal["sequence"].num.int
      if num != height:
        break
      else:
        #if not verify(jsVal, feedId):
        #  echo "failed to verify\n", js["key"].str
        if 1 < height:
          let
            prevStr = await log.get(height-1)
            prevJs = parseJson prevStr
          if js["value"]["previous"].str != prevJs["key"].str:
            echo "previous message mismatch, ",js["value"]["previous"].str," ",prevJs["key"].str
            break
        await log.append($js, num)
        # write message to log file
        if (
          jsVal.kind == JObject and
          jsVal.hasKey("content") and
          jsVal["content"].kind == JObject and
          jsVal["content"].hasKey("mentions")
        ):
          let mentions = jsVal["content"]["mentions"]
          for x in mentions.getElems:
            let link = x["link"].str
            if link[0] == '&':
              let blob = parseBlobId link
              assert(blob.kind == BlobSHA256)
              if node.blobStore.contains(blob.digest):
                echo link," found in blob store"
              else:
                 let (blobReq, blobFut) = peer.newStream()
                 # register stream
                 echo "requesting blob ", link
                 await peer.emitWantBlob(link)
                 #[
                 await peer.ssb.blobsGet(blobReq, link)
                 let digest = await node.blobStore.put(blobFut)
                 # the blob store will drain the stream as dispatch passes data to it
                 if digest != blob.digest:
                   echo "blob mismatch, want ", bin2hex(blob.digest), " got ", bin2hex(digest)
                 else:
                   echo " put to store as ", bin2hex(digest)
                   ]#
  ]#

proc blobsHandler(node: Node, peer: Peer,
           req: Request, js: JsonNode) {.async.} =
  echo "blob request: ", js.pretty
  case js["name"][1].str:
  of "createWants":
    echo "it was createWants"
  else:
    let resp = %*{"message":"unhandled blobs subcommand"}
    await peer.ssb.send(req, $resp)

proc wantBlobs(node: Node, peer: Peer) {.async.} =
  let
    (req, fut) = peer.newStream()
  await peer.ssb.blobsCreateWants(req)
  while true:
    let (active, data) = await fut.read()
    if not active or data == "": break
    let js = parseJson data
    for x in js.getFields.keys:
      let blob = parseBlobId x
      assert(blob.kind == BlobSHA256)
      if node.blobStore.contains(blob.digest):
        echo "peer wantBlobs ", x, " and we have it at ",bin2hex blob.digest
        if peer.blobWantsReq == 0.Request:
          echo "but blob stream is not open"
        else:
          await peer.ssb.blobsHas(peer.blobWantsReq, x)

proc dispatch(node: Node, peer: Peer) {.async.} =
  let (magic, req, data) = await peer.ssb.recv()
  if (magic and End) == End:
    echo "the end: ", data
  if peer.streams.hasKey(req):
    let stream = peer.streams[req]
    if (magic and End) == End:
      echo "completing the stream"
      complete stream
      peer.streams.del(req)
    else:
      if not stream.finished:
        await stream.write(data)
  elif not data.isNil and data != "":
    var
      callName: string
      js: JsonNode
    try:
      js = parseJson data
      callName = js["name"].elems[0].str
    except:
      echo "bad request"
      return
    if peer.handlers.hasKey(callName):
      let handleProc = peer.handlers[callName]
      await handleProc(node, peer, req, js)
    else:
      let msg = %*{"message":callName & " not supported"}
      await peer.ssb.send(req, $msg)

proc process(node: Node, peer: Peer) {.async.} =
  #peer.registerHandler("createHistoryStream", createHistoryStreamHandler)
  peer.registerHandler("blobs", blobsHandler)
  for id, feed in node.follows.pairs:
    await node.replicate(peer, feed, id)
  #asyncCheck node.createFollowStreams(peer)
  asyncCheck node.wantBlobs(peer)
  #let id = parseBlobId "&4DVkVCxbxXBosgCeo1mYxBa/WgUldPOE6osWpVKAHSc=.sha256"
  #echo "requesting ", bin2hex id.digest
  #await peer.emitWantBlob("&4DVkVCxbxXBosgCeo1mYxBa/WgUldPOE6osWpVKAHSc=.sha256")
  while not peer.ssb.sock.isClosed():
    await node.dispatch(peer)

proc connect*(node: Node, pub: SignPublicKey,
              address: string, port: Port): Future[Peer] {.async.} =
  ## Connect to another SSB node.
  let sock = newAsyncSocket()
  await sock.connect(address, port)
  let peer = newNodePeer sock
  await peer.ssb.connect(node.pair, pub)
  node.peers.add(peer)
  result = peer

proc serve*(node: Node) {.async.} =
  ## Start accepting and processing SSB peers.
  node.sock.listen()
  while not node.sock.isClosed():
    let
      clientSock = await node.sock.accept()
      peer = newNodePeer clientSock
    await peer.ssb.accept(node.pair)
    node.peers.add(peer)
    asyncCheck node.process(peer)

proc broadcast*(node: Node) {.async.} =
  ## Start accepting and processing SSB peers
  try:
    node.bcastSock = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered=false)
    node.bcastSock.bindAddr(DefaultPort)
    node.bcastSock.setSockOpt(OptBroadcast, true)
  except:
    echo "failed to bind to broadcast port"
    return

  randomize()
  # seed the generator
  while not node.bcastSock.isClosed():
    let msgFut = node.bcastSock.recv(128)
    # read a broadcast message
    var ready = false
    while not ready:
      await node.announce()
      ready = await withTimeout(msgFut, random(1 shl 14) + (1 shl 13))
      # broadcast an announcement at random intervals between 8 and 24 seconds

    echo "recved ", (await msgFut), " connect from broadcast not implemented"

proc playbackFollows(node: Node, feed: Feed) {.async.} =
  ## Parse a feed and apply transactions such as follow
  let height = await feed.log.height
  var i: int
  while i < height:
    inc i
    let msg = await feed.log.get(i)
    try:
      let
        js = parseJson msg
        content = js["value"]["content"]
      node.parseFollowedMessage(content)
    except:
      echo "failed to parse feed message ",msg

when isMainModule:

  import parseopt, parsecfg, strutils

  var node: Node

  import posix
  onSignal(SIGINT, SIGTERM):
    close node
    quit 0

  proc main() {.async.} =
    var
      cfgPath: string
      optParser = initOptParser()
    optParser.next()
    case optParser.kind:
    of cmdArgument:
      cfgPath = optParser.key
    else:
      echo "please pass a single configuration filename as an argument"
      quit -1

    var cfg = loadConfig(cfgPath)

    var seed: SignSeed
    let
      seedStr = cfg.getSectionValue("ssb", "seed")
    if seedStr.len >= seed.len*2:
      arrayFromString(seed, hex2bin seedStr)
    else:
      randomBytes seed
      cfg.setSectionKey("ssb", "seed", bin2hex seed)
      cfg.writeConfig(cfgPath)

    let
      host = cfg.getSectionValue("ssb", "host")     
      portStr = cfg.getSectionValue("ssb", "port")
      port = if portStr == "": DefaultPort else: Port(parseint portStr)
 
    createDir(BlobsDir)
    createDir(FeedsDir)

    node = newNode(seed, port, host)

    let follows = cfg.getSectionValue("ssb", "follow").split(",")
    for feedStr in follows.items:
      let feedId = parseFeedId feedStr
      # parseFeedId verifies that the feedStr is valid
      node.follow(feedId)
      await node.playbackFollows(node.follows[feedStr])

    for id, feed in node.follows.pairs:
      asyncCheck node.processFeed(feed, parseFeedId id)
      # process incoming feed messages from different peers

    let connect = cfg.getSectionValue("ssb", "connect").split(",")
    for x in connect.items:
      let elems = x.split(":")
      var
        peerId: FeedId
        host: string
        port = DefaultPort
      case elems.len:
      of 3:
        peerId = parseFeedId elems[0]
        host = elems[1]
        port = Port(parseint elems[2])
      of 2:
        peerId = parseFeedId elems[0]
        host = elems[1]
      else:
        echo "ignoring malformed connect string '",x,"'"
        continue
      let
        peer = await node.connect(peerId.key, host, port)
      asyncCheck node.process(peer)

    asyncCheck node.broadcast()
    await node.serve()

  waitFor main()
