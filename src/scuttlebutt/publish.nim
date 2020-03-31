import scuttlebutt/client, scuttlebutt/crypto, scuttlebutt/libsodium/sodium
import scuttlebutt/stringify
import asyncdispatch, streams, strutils, base64, times, parsecfg

proc blobbify*(sbot: SbotClient,
              headers, body: string,
              boxKeys: seq[BoxPublicKey]): seq[BlobId] =
  let
    maxBlob = 0xFFFE - multiboxOverhead(boxKeys.len)
    fullLen = headers.len + body.len
  if fullLen < maxBlob:
    let
      plain = headers & body
      cipher = multibox(plain, boxKeys)
    result = @[sbot.addBlob(cipher)]
  elif headers.len < maxBlob and body.len < maxBlob:
    let
      cipherHeaders = multibox(headers, boxKeys)
      cipherBody = multibox(body, boxKeys)
    result = @[
      sbot.addBlob(cipherHeaders),
      sbot.addBlob(cipherBody)
    ]
  else:
    let
      bulk = headers & body
    result = newSeqOfCap[BlobId](bulk.len div maxBlob)
    for i in countup(bulk.low, bulk.high, maxBlob):
      let
        plain = bulk[i..i+maxBlob]
        cipher = multibox(plain, boxKeys)
      result.add(sbot.addBlob(cipher))

proc publish*(sbot: SbotClient,
             previous: JsonNode,
             blobIds: seq[BlobId],
             blobSize: int): JsonNode =
  ## Publish a blobbed email as an SSB message.
  let
    timestamp = max(
      previous["value"]["timestamp"].num + 1,
      epochTime().BiggestInt)

  var
   mentions = newJArray()
  for id in blobIds:
    mentions.add(%*{ "link": $id})
  var
    jsPost = %*
      {
        "previous": previous["key"],
        "author": previous["value"]["author"],
        "sequence": previous["value"]["sequence"].num + 1,
        "timestamp": timestamp,
        "hash": "sha256",
        "content":
         {
           "type": "rfc822",
           "mentions": mentions,
           "size": blobSize
         }
      }

  sign(jsPost, sbot.pair.sec)
  result = sbot.sendRpc("add", %[jsPost], 0)

proc publish*(sbot: SbotClient,
             blobIds: seq[BlobId],
             blobSize: int): JsonNode =
  let latest = sbot.getLatest
  if  latest.kind == JObject:
    sbot.publish(latest, blobIds, blobSize)
  else:
    let latest = %*
      {
        "key": nil,
        "value":
        {
          "author": "@" & base64.encode(sbot.pair[0]) & ".ed25519",
          "sequence": 0,
          "timestamp": epochTime().BiggestInt
        }
      }
    sbot.publish(latest, blobIds, blobSize)
