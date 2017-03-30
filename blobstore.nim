import asyncfile, asyncdispatch, os
# stdlib

import ./hex, nimSHA2
# nimble

const DirSeperator = "/"

type BlobStore* = object
  root: string
  
proc newBlobStore*(path: string): BlobStore =
  createDir path
  BlobStore(root : path)

proc getPath(store: BlobStore, digest: SHA256Digest): string =
  let hexStr = hex.encode(digest)
  result = (
    store.root & DirSeperator &
    hexStr[0..1] & DirSeperator & hexStr[2..hexStr.high])

proc contains*(store: BlobStore, digest: SHA256Digest): bool =
  existsFile store.getPath(digest)

proc get*(store: BlobStore, digest: SHA256Digest,
          fs: FutureStream[string]) {.async.} =
  let
    path = store.getPath(digest)
  if existsFile path:
    let
      file = openAsync(path, fmRead)
    await file.readToStream(fs)
    close file
  else:
    fs.complete()

proc put*(store: BlobStore, fs: FutureStream[string]): Future[SHA256Digest] {.async.} =
  var ctx: SHA256
  initSHA ctx
  let
    tmpPath = store.root & "/tmp"
    file = openAsync(tmpPath, fmWrite)
    # open temporary file
  while true:
    let (hasValue, value) = await fs.read()
    if hasValue:
      ctx.update(value)
      await file.write(value)
      # hash and write data
    else: break
  close file
  let
    digest = ctx.final
    hexStr = hex.encode(digest)
    subdir = store.root & DirSeperator & hexStr[0..1]
    path = subdir & "/" & hexStr[2..hexStr.high]
    # hash to get final path
  if existsFile(path):
    removeFile tmpPath
  else:
    createDir subdir
    moveFile(tmpPath, path)
  result = digest
