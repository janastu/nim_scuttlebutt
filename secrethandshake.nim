import libsodium/sodium
# local modules

import nimSHA2
# nimble

import net, asyncnet, asyncdispatch
# stdlib

proc fromString[T](str: string): T =
  for i in low(result)..high(result):
    result[i] = str[i]

const

  ChallengeLength = 64
  ClientAuthLength = 16+32+64
  ServerAuthLength = 16+64

type SecretHandshakeError* = object of Exception

proc raiseSH(err: string) =
  raise newException(SecretHandshakeError, err)

type

  Handshake* = ref object
    appKey: AuthKey
    permPair*: SignPair
    permPublic*: SignPublicKey
    tempPair: BoxPair
    localAppMac*, remoteAppMac*: AuthTag
    public*: SignPublicKey # of the other side
    secret1: BoxSecretKey
    digest1: SHA256Digest
    secret2: SecretBoxKey
    digest2: SHA256Digest
    secret3*: SecretBoxKey
    a_bob: array[32, char]
    b_alice: array[32, char]
    hello: string

proc newHandshake(perm: SignPair, appKey: AuthKey): Handshake =
  Handshake(
    appKey : appKey,
    permPair : perm,
    tempPair : crypto_box_keypair()
  )

proc sendChallenge(sock: Socket | AsyncSocket, h: Handshake) {.multisync.} =
  h.localAppMac = crypto_auth($h.tempPair.pub, h.appKey)
  let challenge = $h.localAppMac & $h.tempPair.pub

  await sock.send(challenge)

proc recvChallenge(sock: Socket | AsyncSocket, h: Handshake) {.multisync.} =
  let challenge = await recv(sock, ChallengeLength)
  if (challenge.len == ChallengeLength):
    h.remoteAppMac = fromString[AuthTag](challenge[low(challenge)..31])
    h.public = fromString[SignPublicKey](challenge[32..high(challenge)])

    if crypto_auth_verify(h.remoteAppMac, $h.public, h.appKey):
      h.secret1 = crypto_scalarmult(h.tempPair.sec, h.public)
      h.digest1 = computeSHA256($h.secret1)
      return

  raiseSH "phase 1 challenge failed verification"

proc accept*(sock: Socket | AsyncSocket,
             pair: SignPair, appKey: AuthKey): Future[Handshake] {.multisync.} =
  ## Perform a secret handshake in the server role.
  let
    shake = newHandshake(pair, appKey)
    h = shake

  await recvChallenge(sock, shake)
  await sendChallenge(sock, shake)

  block recvClientAuth:
    let auth = await recv(sock, ClientAuthLength)
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

      raise newException(SystemError, "client authentication failed")

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

    await send(sock, accept)

  result = shake


proc connect*(sock: Socket | AsyncSocket,
              pair: SignPair,
              public: SignPublicKey,
              appKey: AuthKey): Future[Handshake] {.multisync.} =
  ## Perform a secret handshake in the client role.
  let shake = newHandshake(pair, appKey)
  shake.permPublic = public

  await sendChallenge(sock, shake)
  await recvChallenge(sock, shake)

  block sendClientAuth:
    let pubKey = crypto_sign_ed25519_pk_to_curve25519(public)
    shake.a_bob = crypto_scalarmult(shake.tempPair.sec, pubKey)

    var sha = initSHA[SHA256]()
    sha.update($appKey)
    sha.update($shake.secret1)
    sha.update($shake.a_bob)
    shake.digest2 = sha.final()

    let
      msg = $appKey & $public & $shake.digest1
      sig = crypto_sign_detached(msg, shake.permPair.sec)
    shake.hello = $sig & $shake.permPair.pub

    var nonce: SecretBoxNonce
    # use a zeroed nonce
    let auth = crypto_secretbox_easy(shake.hello, nonce, shake.digest2)
    await send(sock, auth)

  block recvServerAccept:
    let auth = await recv(sock, ServerAuthLength)

    if auth.len == ServerAuthLength:
      let
        sk = crypto_sign_ed25519_sk_to_curve25519(shake.permPair.sec)
      shake.b_alice = crypto_scalarmult(sk, shake.public)
      var sha = initSHA[SHA256]()
      sha.update($appKey)
      sha.update($shake.secret1)
      sha.update($shake.a_bob)
      sha.update($shake.b_alice)
      shake.secret3 = sha.final()

      var nonce: SecretBoxNonce
      let
        msg = $appKey & shake.hello & $shake.digest1
        plain = crypto_secretbox_open_easy(auth, nonce, shake.secret3)

      if plain != nil:
        let
          sig = fromString[SignDetached](plain)

        if crypto_sign_verify_detached(sig, msg, public):
          break recvServerAccept

    raiseSH "server authentication failed"

  result = shake
