import json, os, endians, asyncfile, asyncdispatch

const
  Magic = 0x01020304050607.int64

type
  LogFile* = ref object
    file: AsyncFile
    msgHeight: int64
    appendPos: int64
    index: string

proc openLogFile*(filename: string, mode: FileMode = fmRead): LogFile =
  ## Open a log file.
  # TODO take magic as a template argument
  LogFile(file : openAsync(filename, mode))

proc init(log: LogFile) {.async.} =
  let fileSize = log.file.getFileSize()
  if fileSize == 0:
    var
      fileMagic = newString(sizeof(int64))
      nativeMagic = Magic
    bigEndian64(addr fileMagic[fileMagic.low], addr nativeMagic)
    log.msgHeight = 0
    log.index = newStringOfCap(64)
    log.index.setLen sizeof(int64)
    await log.file.write(fileMagic)
    await log.file.write("\0\0\0\0\0\0\0\0")
    log.appendPos = sizeof(fileMagic)
  else:
    log.file.setFilePos(0)
    var
      nativeMagic: int64
      fileMagic = await log.file.read(sizeof(int64))
    assert(fileMagic.len == sizeof(int64))
    bigEndian64(addr nativeMagic, addr fileMagic[fileMagic.low])
    if (nativeMagic != Magic):
      raise newException(ValueError, "bad log file magic ")

    log.file.setFilePos(fileSize - sizeof(int64))
    var fileHeight = await log.file.read(sizeof(int64))
    bigEndian64(addr log.msgHeight, addr fileHeight[fileHeight.low])

    let indexSize = (log.msgHeight+1) * sizeof(int64)
    if (indexSize+log.msgHeight) >= fileSize:
      raise newException(ValueError, "bad log file height")

    log.file.setFilePos((fileSize - indexSize) - sizeof(int64))
    log.index = await log.file.read(indexSize.int)
    assert(log.index.len == indexSize)
    log.appendPos = fileSize - indexSize

proc close*(log: LogFile) =
  close log.file
  log.index.setLen(0)
  log.msgHeight = 0
  log.appendPos = 0

proc height*(log: LogFile): Future[int] {.async.} =
  if log.appendPos == 0:
    await init(log)
  result = log.msgHeight.int

proc append*(log: LogFile, msg: string, height: int) {.async.} =
  assert(height == log.msgHeight+1)
  if log.appendPos == 0:
    await init(log)
  let
    indexHeightOff = log.index.len
    indexMsgOff = indexHeightOff- sizeof(int64)
  log.index.setLen(indexHeightOff + sizeof(int64))
  bigEndian64(
    addr log.index[indexMsgOff],
    addr log.appendPos)
  bigEndian64(
    addr log.index[indexHeightOff],
    addr log.msgHeight)
  log.file.setFileSize(log.appendPos + msg.len + log.index.len)
  log.file.setFilePos(log.appendPos + msg.len)
  await log.file.write(log.index)
  inc log.msgHeight
  log.file.setFilePos(log.appendPos)
  await log.file.write(msg)
  log.appendPos = log.appendPos + msg.len

proc get*(log: LogFile, height: int): Future[string] {.async.} =
  ## Access to log messages from index one.
  if log.appendPos == 0:
    await init(log)
  assert(0 < height)
  assert(log.msgHeight >= height)
  let i = height-1
  assert(i*sizeof(int64) < log.index.high)
  var off, next: int64
  let iOff = i*sizeof(int64)
  bigEndian64(addr off, addr log.index[iOff])
  if height == log.msgHeight.int:
    next = log.appendPos
  else:
    bigEndian64(addr next, addr log.index[iOff+sizeof(int64)])
  log.file.setFilePos(off)
  result = await log.file.read((next-off).int)
