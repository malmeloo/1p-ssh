import asyncnet, net, nativesockets, asyncdispatch, os, options
import ./proto, ./datatypes

const AGENT_PATHS = [
  "~/.1password/agent.sock",
  "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
]


type
  ProxyAgentClient* = object
    path*: string
    sock: AsyncSocket

proc newProxyAgentClient*(path: string): ProxyAgentClient =
  ProxyAgentClient(
    sock: newAsyncSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP),
    path: path
  )

proc connect*(agentc: ProxyAgentClient) {.async.} =
  try:
    await agentc.sock.connectUnix(agentc.path)
  except OSError:
    raise newException(OSError, "Could not connect to 1Password agent!")

proc close*(agentc: ProxyAgentClient) =
  agentc.sock.close()

proc setHostname*(agentc: ProxyAgentClient, hostname: string) {.async.} =
  let msg = AgentMessage(
    mType: ProtocolMessageType.SSH_AGENTC_EXTENSION,
    mData: writeString("1p-ssh-fix") & writeString(hostname)
  )
  await agentc.sock.sendMessage(msg)


proc getAgentPath*(): Option[string] =
  for path in AGENT_PATHS:
    let fullPath = expandTilde(path)

    try:
      let s = newSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)
      s.connectUnix(fullPath)
      s.close()
    except OSError:
      continue

    result = some(fullPath)
