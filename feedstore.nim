include logfile

import ./hex, crypto

const DirSeperator = "/"

type FeedStore* = object
  root: string
  
proc newFeedStore*(path: string): FeedStore =
  createDir path
  FeedStore(root : path)

proc getPath(store: FeedStore, id: FeedId): string =
  assert(id.kind == FeedEd25519)
  let hexStr = hex.encode(id.key)
  result = (
    store.root & DirSeperator &
    hexStr[0..1] & DirSeperator & hexStr[2..hexStr.high])

proc contains*(store: FeedStore, id: FeedId): bool =
  existsFile store.getPath(id)

proc get*(store: FeedStore, id: FeedId): LogFile =
  assert(id.kind == FeedEd25519)
  let
    hexStr = hex.encode(id.key)
    subdir = store.root & DirSeperator & hexStr[0..1]
    path = subdir & "/" & hexStr[2..hexStr.high]
  if existsFile path:
    result = openLogFile(path, fmReadWriteExisting)
  else:
    createDir subdir
    result = openLogFile(path, fmReadWrite)
