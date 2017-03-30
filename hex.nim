proc nibbleFromChar(c: char): int =
  case c
  of '0'..'9': result = (ord(c) - ord('0'))
  of 'a'..'f': result = (ord(c) - ord('a') + 10)
  of 'A'..'F': result = (ord(c) - ord('A') + 10)
  else: discard 255

proc decode*(str: string): string =
  let length = len(str) div 2
  result = newString(length)
  for i in result.low..result.high:
    result[i] = chr((nibbleFromChar(str[2 * i]) shl 4) or nibbleFromChar(str[2 * i + 1]))

proc nibbleToChar(nibble: int): char =
  const byteMap = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
  const byteMapLen = len(byteMap)
  try:
    if nibble < byteMapLen:
      return byteMap[nibble];
  except ValueError:
    echo "Hex string character out of range for valid hex char"

template encodeTmpl(str: untyped): typed =
  let length = (len(str))
  result = newString(length * 2)
  for i in str.low..str.high:
    let a = ord(str[i]) shr 4
    let b = ord(str[i]) and ord(0x0f)
    result[i * 2] = nibbleToChar(a)
    result[i * 2 + 1] = nibbleToChar(b)

#proc encode*(bin: string): string =
#  encodeTmpl(bin)

proc encode*(bin: openarray[char]): string =
  encodeTmpl(bin)

when isMainModule:
  assert encode("The sun so bright it leaves no shadows") == "5468652073756e20736f20627269676874206974206c6561766573206e6f20736861646f7773"
  const longText = """Man is distinguished, not only by his reason, but by this
    singular passion from other animals, which is a lust of the mind,
    that by a perseverance of delight in the continued and indefatigable
    generation of knowledge, exceeds the short vehemence of any carnal
    pleasure."""
  assert encode(longText) == "4d616e2069732064697374696e677569736865642c206e6f74206f6e6c792062792068697320726561736f6e2c2062757420627920746869730a2020202073696e67756c61722070617373696f6e2066726f6d206f7468657220616e696d616c732c2077686963682069732061206c757374206f6620746865206d696e642c0a20202020746861742062792061207065727365766572616e6365206f662064656c6967687420696e2074686520636f6e74696e75656420616e6420696e6465666174696761626c650a2020202067656e65726174696f6e206f66206b6e6f776c656467652c2065786365656473207468652073686f727420766568656d656e6365206f6620616e79206361726e616c0a20202020706c6561737572652e"
  const tests = ["", "abc", "xyz", "man", "leisure.", "sure.", "erasure.",
                 "asure.", longText]
  for t in items(tests):
    assert decode(encode(t)) == t
