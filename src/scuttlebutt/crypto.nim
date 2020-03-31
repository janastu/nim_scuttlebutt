import base64, strutils, json, tables
# stdlib

import nimSHA2
# nimble

import libsodium/sodium
# local

export SignPublicKey, BoxPublicKey

proc fromString[T](str: string): T =
  for i in low(result)..high(result):
    result[i] = str[i]

type
  FeedKind* = enum
    FeedEd25519

  FeedId* = ref FeedIdObj
  FeedIdObj = object
    case kind*: FeedKind
    of FeedEd25519: key*: SignPublicKey

const
  FeedSuffix = ".ed25519"

proc `$`*(f: FeedId): string =
  assert(f.kind == FeedEd25519)
  "@"& base64.encode(f.key)& FeedSuffix

proc `%`*(f: FeedId): JsonNode =
  newJString $f

proc parseFeedId*(str: string): FeedId =
  if str[0] == '@' and str.endsWith(FeedSuffix):
    let
      bin = base64.decode str[1..str.high-FeedSuffix.len]
      key = fromString[SignPublicKey](bin)
    return FeedId(kind: FeedEd25519, key: key)
  raise newException(ValueError, "invalid feed id '$#'" % str)

proc boxPublicKey*(feed: FeedId): BoxPublicKey =
  assert(feed.kind == FeedEd25519)
  crypto_sign_ed25519_pk_to_curve25519(feed.key)

proc merge*(x: var FeedId, y: FeedId) =
  ## merge
  assert(x.kind == y.kind)
  for i in x.key.low..x.key.high:
    let
      a = x.key[i].int
      b = y.key[i].int
    x.key[i] = (a or b).char

proc contains*(x, y: FeedId): bool =
  assert(x.kind == FeedEd25519 and y.kind == FeedEd25519)
  for i in x.key.low..x.key.high:
    let
      a = x.key[i].int
      b = y.key[i].int
    if b != (a and b):
      return false
  true

type
  MsgKind* = enum
    MsgSHA256

  MsgId* = ref MsgIdObj
  MsgIdObj = object
    case kind*: MsgKind
    of MsgSHA256: digest*: SHA256Digest

const
  MsgSuffix = ".sha256"

proc `$`*(id: MsgId): string =
  assert(id.kind == MsgSHA256)
  "%"& base64.encode(id.digest)& MsgSuffix

proc parseMsgId*(str: string): MsgId =
  if str[0] == '%' and str.endsWith(MsgSuffix):
    let
      bin = base64.decode str[1..str.high-MsgSuffix.len]
      digest = fromString[SHA256Digest](bin)
    return MsgId(kind: MsgSHA256, digest: digest)
  raise newException(ValueError, "invalid message id '$#'" % str)

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
      ValueError, "invalid or unhandled blob digest string '" & str & "'")

const
  RecipientPlainLen = 1 + crypto_secretbox_KEYBYTES
  RecipientCipherLen = crypto_secretbox_MACBYTES + RecipientPlainLen

proc multiboxOverhead*(recipients: int): int =
  result =
    crypto_secretbox_NONCEBYTES +
    crypto_box_PUBLICKEYBYTES +
    crypto_secretbox_MACBYTES +
    recipients * (
      RecipientCipherLen
    )

proc multibox*(msg: string, recipients: seq[Curve25519Pk]): string =
  assert(recipients.len > 0 and recipients.len <= high(uint8).int)
  var
    nonce = newRandom[SecretBoxNonce]()
    onetime = crypto_box_keypair()
    key = newRandom[SecretBoxKey]()
    keyKey = newString RecipientPlainLen
    cipherKeys = newStringOfCap(
      recipients.len * RecipientCipherLen)

  keyKey[0] = recipients.len.char
  copymem(addr keyKey[1], addr key[0], key.len)

  for rPk in items recipients:
    let
      key = crypto_scalarmult(onetime[1], rPk)
      cipher = crypto_secretbox_easy(keyKey, nonce, key)
    assert(cipher.len == RecipientCipherLen)
    cipherKeys.add(cipher)
  let
    ciphertext = crypto_secretbox_easy(msg, nonce, key)
  result = newStringOfCap nonce.len + onetime[0].len + cipherKeys.len + cipherText.len
  result.setLen(nonce.len + onetime[0].len)
  copymem(addr result[0], addr nonce[0], nonce.len)
  copymem(addr result[nonce.len], addr onetime[0][0], onetime[0].len)
  result.add(cipherKeys)
  result.add(cipherText)

proc multiboxOpen*(cipherText: string, secret: Curve25519Sk): string =
  let
    nonce = fromString[SecretBoxNonce](cipherText)
    onetimePk = fromString[BoxPublicKey](cipherText[nonce.len..high(cipherText)])
    myKey = crypto_scalarmult(secret, onetimePk)

  var i = nonce.len + onetimePk.len
  while i < high(cipherText)-RecipientCipherLen:
    try:
      let
        keyKeyCipher = cipherText[i..i+RecipientCipherLen-1]
        keysKey = crypto_secretbox_open_easy(
          keyKeyCipher,
          nonce, myKey
        )
        numKeys = keysKey[0].int
        key = fromString[SecretBoxKey](keysKey[1..high(keysKey)])
        start = nonce.len + onetimePk.len + numKeys * RecipientCipherLen
      return crypto_secretbox_open_easy(
        cipherText[start..high(cipherText)],
        nonce, key
      )

    except SodiumError:
      i = i+RecipientCipherLen

const
  SigSuffix = ".sig.ed25519"

proc sign*(obj: var JsonNode, key: Ed25519Sk) =
  ## Sign a JSON object.
  assert(obj.kind == JObject and not obj.hasKey("signature"))
  let
    msg = obj.pretty
    sig = crypto_sign_detached(msg, key)
    str = base64.encode(sig, newLine="") & SigSuffix
  obj["signature"] = newJString str

proc verify*(js: JsonNode, key: Ed25519Pk): bool =
  ## Verify a signed JSON object.
  assert(js.kind == JObject and js.hasKey("signature"))
  let
    obj = newJObject()
  for field in js.getFields.pairs:
    if field[0] != "signature":
      obj[field[0]] = field[1]
  var
    str = js["signature"].str
  str.removeSuffix(SigSuffix)
  let
    msg = pretty(obj)
    bin = base64.decode(str)
    sig = fromString[SignDetached](bin)
  crypto_sign_verify_detached(sig, msg, key)

proc verify*(obj: JsonNode, feedId: FeedId): bool =
  assert(feedId.kind == FeedEd25519)
  verify(obj, feedId.key)

when isMainModule:
  import unittest, times

  suite "mulitbox":

    test "  one recipient":
      let
        msgIn = $getTime()
        pair = crypto_box_keypair()
        recipients = @[pair[0]]
        ciphertext = multibox(msgIn, recipients)
        msgOut = multiboxOpen(ciphertext, pair[1])
      assert(msgIn == msgOut)
      assert(ciphertext.len - msgIn.len == multiboxOverhead(1))

    test "  two recipients":
      let
        msgIn = $getTime()
        pair = crypto_box_keypair()
        recipients = @[pair[0], newRandom[Curve25519Pk]()]
        ciphertext = multibox(msgIn, recipients)
        msgOut = multiboxOpen(ciphertext, pair[1])
      assert(msgIn == msgOut)
      assert(ciphertext.len - msgIn.len == multiboxOverhead(2))

    test "three recipients":
      let
        msgIn = $getTime()
        pair = crypto_box_keypair()
        recipients = @[pair[0], newRandom[Curve25519Pk](), newRandom[Curve25519Pk]()]
        ciphertext = multibox(msgIn, recipients)
        msgOut = multiboxOpen(ciphertext, pair[1])
      assert(msgIn == msgOut)
      assert(ciphertext.len - msgIn.len == multiboxOverhead(3))

    test "  max recipients":
      let
        msgIn = $getTime()
        pair = crypto_box_keypair()

      var
        recipients = newSeq[Curve25519Pk](255)
      recipients[0] = pair[0]
      for i in low(recipients)..high(recipients):
        randomBytes recipients[i]
      recipients[pair[1][0].uint8.int] = pair[0]
        # randomly place the key that works

      let
        ciphertext = multibox(msgIn, recipients)
        msgOut = multiboxOpen(ciphertext, pair[1])
      assert(msgIn == msgOut)
      assert(ciphertext.len - msgIn.len == multiboxOverhead(255))

  suite "sign":

    test "succeed":
      let
        pair = crypto_sign_keypair()
      var
        objIn = %*
          {
            "public": encode(pair[0], newLine=""),
            "secret": encode(pair[1], newLine=""),
            "now": getTime().int,
            "foobar": nil
            # throw some noise in
          }
      objIn.sign(pair[1])
      let
        objOut = parseJson($objIn)
      assert(verify(objOut, pair[0]))

    test "fail":
      let
        pair1 = crypto_sign_keypair()
        pair2 = crypto_sign_keypair()
      var
        objIn = %*
          {
            "public": encode(pair1[0], newLine=""),
            "secret": encode(pair1[1], newLine=""),
            "now": getTime().int,
            "foobar": nil
            # throw some noise in
          }
      objIn.sign(pair1[1])
      let
        objOut = parseJson($objIn)
      assert(not verify(objOut, pair2[0]))

    test "stringfy":
      let
        control = """
{
  "foo": {
    "bar": null
  }
}"""
        testJson = parseJson(control)
        test = pretty(testJson)
      assert(test == control)
