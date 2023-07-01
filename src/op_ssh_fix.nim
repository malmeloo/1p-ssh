import os, asyncdispatch, options, posix, osproc, strutils, strformat
import cligen
import ./agentproxy, ./agentc, ./installbin

const YES = ["y", "yes", "ye"]

type EKeyboardInterrupt = object of Defect

setControlCHook(proc() {.noconv.} =
  raise newException(EKeyboardInterrupt, "KeyboardInterrupt")
)


proc askYesNo(prompt: string, default: bool = true): bool =
  write(stdout, prompt & (if default: " [Y/n]" else: " [y/N]") & ": ")
  var input = toLowerAscii(readLine(stdin))
  
  return if input == "": default else: input in YES

proc getProxyAgentPath(): string =
  getConfigDir() / "1password-agent-proxy.sock"

proc getSSHHostname(bin: string, args: seq[string]): string =
  let p = startProcess(bin, "", @["-G"] & args)
  for line in p.lines:
    if line.startsWith "hostname":
      let hostname = line.split()[1 ..^ 1]
      return hostname.join " "

proc getProxyAgentClient(): Option[ProxyAgentClient] =
  let agentPath = getAgentPath()
  if agentPath.isNone:
    echo "WARNING: Could not find 1Password agent path, is it set up and running?"
    return none(ProxyAgentClient)

  let agentClient = newProxyAgentClient(getProxyAgentPath())
  try:
    waitFor agentClient.connect()
  except OSError:
    echo "WARNING: Cannot connect to 1Password agent proxy; is the background process running?"
    return none(ProxyAgentClient)
  
  return some(agentClient)


proc proxy() =
  let agentPath = getAgentPath()
  if agentPath.isNone:
    echo "ERROR: Could not find 1Password agent path, is it set up and running?"
    quit 1

  let proxyPath = getProxyAgentPath()
  removeFile(proxyPath)

  try:
    waitFor serveProxy(proxyPath, agentPath.get)
  except EKeyboardInterrupt:
    echo "Shutting down..."

    discard tryRemoveFile(proxyPath)
    quit(0)
  finally:
    echo "Unknown error"

    discard tryRemoveFile(proxyPath)
    quit(0)

proc ssh(cmd: seq[string]) = 
  let sshBin = findExe("ssh")
  if sshBin.len == 0:
    echo "ERROR: Could not find SSH executable in PATH!"
    quit 1
  
  let agentClient = getProxyAgentClient()

  if agentClient.isSome:
    let hostname = getSSHHostname(sshBin, cmd)
    if hostname.len > 0:
      try:
        waitFor agentClient.get.setHostname(hostname)
      except OSError:
        echo "WARNING: Could not send hostname to agent proxy; SSH might try incorrect keys\n"

    putEnv("SSH_AUTH_SOCK", agentClient.get.path)
    agentClient.get.close()

  let args = allocCStringArray @[sshBin] & cmd
  discard execv(sshBin.cstring, args)


proc install() =
  echo "*** 1P-SSH installation wizard ***"

  var binPath = getAppFilename()

  let target = getInstallTarget()
  let targetP = "~/" & relativePath(target, getHomeDir())
  if askYesNo(fmt"[ ] Install 1P-SSH to {targetP}?", true):
    if copyBin(target):
      echo "Successfully installed!"
      binPath = target
    else:
      echo "Install failed!"
      echo "Please stop any running proxies and try again."
  echo ""
  
  if checkSSHAlias():
    echo "Skipping SSH alias setup since it already appears to be installed"
  else:
    echo "It is possible to symlink the 'ssh' command to 1P-SSH for the current user. This will allow you to use the regular SSH commands"
    echo "and make 1P-SSH completely transparent. If you refuse, you must invoke 1P-SSH's 'ssh' subcommand every time you want to connect"
    echo "to a remote host, and external tools might not integrate properly. It is always possible to undo this change."
    if askYesNo(fmt"[ ] Install local SSH alias?", true):
      if not aliasSSH(binPath):
        echo "Alias installation failed, please try again"
      else:
        echo "Alias installed! You may have to restart your shell for the changes to take effect."
  echo ""
  
  if askYesNo(fmt"[ ] Install systemd user service?", true):
    echo fmt"Creating systemd service for {binPath}"
    if writeSystemdService(binPath):
      echo "Success!"
    else:
      echo "Failed to create or enable systemd service"
  echo ""

  let confStatus = checkSSHAgentStatus()
  if confStatus == SSHConfigStatus.PROXY_INSTALLED:
    echo "Skipping SSH config installation since it already appears to be configured correctly."
    return

  if askYesNo(fmt"[ ] Automatically update SSH config to use 1P-SSH proxy?", true):
    discard updateSSHConfig(confStatus, getProxyAgentPath())

proc mergeParams*(cmdNames: seq[string], cmdLine=commandLineParams()): seq[string] =
  if cmdNames.len > 1 and cmdNames[1] == "ssh":
    "--" & cmdLine
  else:
    cmdLine

proc main() =
  try:
    dispatchMulti([proxy], [ssh], [install])
  except EKeyboardInterrupt:
    echo "\nExiting"
    quit 0


when isMainModule: 
  main()
