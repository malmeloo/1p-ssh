import endians


proc readBEuint32*(inp: var string): uint32 =
  bigEndian32(addr result, addr inp[0])
  inp = inp[4 ..^ 1]

proc writeBEuint32*(inp: uint32): string =
  result = newString(4)
  bigEndian32(result[0].addr, inp.unsafeAddr)


proc readString*(inp: var string): string =
  let strLen = readBEuint32(inp)
  result = inp[0 ..< strLen]
  inp = inp[strLen ..^ 1]

proc writeString*(inp: string): string =
  writeBEuint32(inp.len.uint32) & inp


proc readStringSequence*(inp: var string): seq[string] =
  while inp.len > 0:
    result.add readString(inp)

proc writeStringSequence*(inp: seq[string]): string =
  for str in inp:
    result.add writeString(str)
