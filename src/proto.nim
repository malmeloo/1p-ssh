import asyncnet, endians, nativesockets, asyncdispatch, strformat, strutils, base64
import nimSHA2
import ./datatypes

const READ_CHUNK_SIZE = 256


type ProtocolMessageType* = enum
  SSH_AGENT_FAILURE = 5'u8
  SSH_AGENT_SUCCESS = 6'u8

  SSH_AGENTC_REQUEST_IDENTITIES = 11'u8
  SSH_AGENT_IDENTITIES_ANSWER = 12'u8

  SSH_AGENTC_SIGN_REQUEST = 13'u8
  SSH_AGENT_SIGN_RESPONSE = 14'u8

  SSH_AGENTC_ADD_IDENTITY = 17'u8
  SSH_AGENTC_REMOVE_IDENTITY = 18'u8
  SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19'u8

  SSH_AGENTC_ADD_SMARTCARD_KEY = 20'u8
  SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21'u8

  SSH_AGENTC_LOCK = 22'u8
  SSH_AGENTC_UNLOCK = 23'u8

  SSH_AGENTC_ADD_ID_CONSTRAINED = 25'u8
  SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26'u8

  SSH_AGENTC_EXTENSION = 27'u8
  SSH_AGENT_EXTENSION_FAILURE = 28'u8


type
  AgentMessage* = object
    mType*: ProtocolMessageType
    mData*: string
  KeyIdentity* = object of RootObj
    kType*: string
    kData*: seq[string]
    kFp*: string
    kComment*: string

proc `$`*(m: AgentMessage): string =
  fmt"AgentMessage(mType: {m.mType}, mData: {m.mData.len} bytes)"
proc `$`*(k: KeyIdentity): string =
  fmt"KeyIdentity(kType: {k.kType}, kComment: {k.kComment}, kData: {k.kData.len} chunks)"

proc fingerprint(blob: string): string =
  "SHA256:" & encode(computeSHA256(blob)).strip(chars = {'='})

proc readKey(inp: var string): KeyIdentity =
  # A single key entry looks like this:
  #
  # key blob: string
  # |-> key type: string
  # |-> [ more fields depending on key type ]
  # key comment: string
  var keyBlob = readString(inp)
  let fp = keyBlob.fingerprint

  let keyType = readString(keyBlob)
  let keyData = readStringSequence(keyBlob)

  let keyComment = readString(inp)

  return KeyIdentity(
    kType: keyType,
    kData: keyData,
    kFp: fp,
    kComment: keyComment
  )

proc writeKey(key: KeyIdentity): string =
  let keyData = writeStringSequence(key.kData)
  let keyType = writeString(key.kType)
  
  let keyBlob = writeString(keyType & keyData)

  let keyComment = writeString(">" & key.kComment)

  return keyBlob & keyComment


proc readMessage*(sock: AsyncSocket): Future[AgentMessage] {.async.} =
  var msgLen: uint32
  var res = await sock.recvInto(addr msgLen, 4)
  if res < 4:
    raise newException(OSError, "Disconnected while reading message length")
  bigEndian32(addr msgLen, addr msgLen)

  echo msgLen.int.intToStr & " total len"

  var msgType: uint8
  res = await sock.recvInto(addr msgType, 1)
  if res < 1:
    raise newException(OSError, "Disconnected while reading message type")

  var
    toRead = msgLen.int - 1
    msgData = ""
  while toRead > 0:
    let m = await sock.recv(min(READ_CHUNK_SIZE, toRead))
    if m.len == 0:
      raise newException(OSError, "Disconnected while reading message data")

    toRead -= m.len
    msgData &= m

  return AgentMessage(mType: ProtocolMessageType(msgType), mData: msgData)

proc sendMessage*(sock: AsyncSocket, msg: AgentMessage) {.async.} =
  var msgLen: uint32 = msg.mData.len.uint32 + 1
  bigEndian32(addr msgLen, addr msgLen)
  var msgType = msg.mType

  await sock.send(addr msgLen, 4)
  await sock.send(addr msgType, 1)
  await sock.send(msg.mData)


proc parseKeys*(inp: string): seq[KeyIdentity] =
  var keyString = inp[0 ..^ 1]
  var numKeys = readBEuint32(keyString)

  while numKeys > 0:
    result.add readKey(keyString)

    numKeys -= 1

proc writeKeys*(keys: seq[KeyIdentity]): string =
  result &= writeBEuint32(keys.len.uint32)
  for key in keys:
    result &= writeKey(key)
