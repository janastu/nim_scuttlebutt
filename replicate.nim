import secrethandshake, json


proc createHistoryStream(peer: Peer, params: JsonNode): Future[JsonNode] {.async.} =
  ## Fetch messages from a specific user, ordered by sequence numbers.
  #{"name":["createHistoryStream"],"args":[{"id":"@O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=.ed25519","seq":1,"live":true,"keys":false}],"type":"source"}

#[
   //keep track of maximum requested value, per feed.
    sbot.createHistoryStream.hook(function (fn, args) {
      var upto = args[0] || {}
      var seq = upto.sequence || upto.seq
      to_recv[upto.id] = Math.max(to_recv[upto.id] || 0, seq)
      if(this._emit) this._emit('call:createHistoryStream', args[0])

      //if we are calling this locally, skip cleverness
      if(this===sbot) return fn.call(this, upto)

      debounce.set()

      //handle creating lots of histor streams efficiently.
      //maybe this could be optimized in map-filter-reduce queries instead?
      if(to_send[upto.id] == null || (seq > to_send[upto.id])) {
        upto.old = false
        if(!upto.live) return pull.empty()
        var pushable = listeners[upto.id] = listeners[upto.id] || []
        var p = Pushable(function () {
          var i = pushable.indexOf(p)
          pushable.splice(i, 1)
        })
        pushable.push(p)
        pushable.sequence = upto.sequence
        return p
      }
      return fn.call(this, upto)
    })


   sbot.on('rpc:connect', function(rpc) {
      // this is the cli client, just ignore.
      if(rpc.id === sbot.id) return
      //check for local peers, or manual connections.
      localPeers()
      var drain
      sbot.emit('replicate:start', rpc)
      rpc.on('closed', function () {
        sbot.emit('replicate:finish', to_send)
      })
      var SYNC = false
      pull(
        upto({live: opts.live}),
        drain = pull.drain(function (upto) {
          if(upto.sync) return
          feeds++
          debounce.set()
          pull(
            rpc.createHistoryStream({
              id: upto.id,
              seq: (upto.sequence || upto.seq || 0) + 1,
              live: true,
              keys: false
            }),
            sbot.createWriteStream(function (err) {
              if(err) console.error(err.stack)

              feeds--
              debounce.set()
            })
          )

        }, function (err) {
          if(err)
            sbot.emit('log:error', ['replication', rep.id, 'error', err])
        })
      )
    })
]#

  result = %"what?"

registerRpc(createHistoryStream, "createHistoryStream")
