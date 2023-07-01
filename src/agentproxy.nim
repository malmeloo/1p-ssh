import asyncnet, nativesockets, asyncdispatch, strformat, os
import ./proto, ./op, ./datatypes, ./hostmatching

var clientNum = 0
var currentHost: string = ""

proc processClient(client: AsyncSocket, connectPath: string, id: int) {.async.} =
  let agent = newAsyncSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)
  await agent.connectUnix(connectPath)

  while true:
    try:
      var
        doForward = true
        response: AgentMessage

      let clientMessage = await client.readMessage()
      echo "(client > us) " & $clientMessage
      if clientMessage.mType == SSH_AGENTC_EXTENSION:
        var data = clientMessage.mData
        let extType = readString(data)
        
        if extType == "1p-ssh-fix":
          currentHost = readString(data)
          echo fmt"Received request for host '{currentHost}'"

          response = AgentMessage(mType: SSH_AGENT_SUCCESS)
          doForward = false

      if not doForward:
        echo "Acting as authorative agent"
      else:
        await agent.sendMessage(clientMessage)
        echo "(us > agent) " & $clientMessage

        response = await agent.readMessage()
        echo "(agent > us) " & $response

        if response.mType == SSH_AGENT_IDENTITIES_ANSWER:
          echo "Intercepting keys response"
          let providedKeys = parseKeys(response.mData)

          var savedKeys: seq[SavedKey]
          try:
            savedKeys = getKeys()

            savedKeys.sortKeys(currentHost)
            let finalKeys = matchIdentities(providedKeys, savedKeys)
            response.mData = writeKeys(finalKeys)
          except CatchableError:
            echo "Aborting interception, proxying regular response."

      await client.sendMessage(response)
      echo "(us > client) " & $response
    except OSError:
      echo fmt"Client {id} disconnected"
      client.close()
      return

proc serveProxy*(bindPath, connectPath: string) {.async.} =
  let server = newAsyncSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)
  server.bindUnix(bindPath)
  setFilePermissions(bindPath, {fpUserRead, fpUserWrite})

  server.listen()

  echo fmt"Agent proxy ready on {bindPath}"
  
  while true:
    let client = await server.accept()
    clientnum = (clientNum + 1) mod 100
    echo fmt"Client {clientNum} connected"
    
    asyncCheck processClient(client, connectPath, clientNum)
