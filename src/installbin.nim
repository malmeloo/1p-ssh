import os, osproc, strutils, strformat, sequtils, nre

const DEBUG = false

const INSTALL_PATH = "~/.local/bin/"

const SSH_CONF_PATH = "~/.ssh/config"

const SYSTEMD_SERVICE_NAME = "1p-ssh-agent-proxy"
const SYSTEMD_SERVICE_PATH = fmt"~/.config/systemd/user/{SYSTEMD_SERVICE_NAME}.service"
const SYSTEMD_SERVICE = """
[Unit]
Description=1P-SSH Agent Proxy
After=network.target

[Service]
Type=simple
ExecStart={bin} proxy
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
"""
const SYSTEMD_ENABLE_CMD* = "systemctl --user daemon-reload" &
  fmt"&& systemctl --user enable {SYSTEMD_SERVICE_NAME}"
const SYSTEMD_START_CMD* = fmt"systemctl --user start {SYSTEMD_SERVICE_NAME}"

let AGENT_SOCK_1P_RE = re"(?m)^\s+[^#]I?dentityAgent\s.+?1password.+?agent\.sock$"
let AGENT_SOCK_PROXY_RE = re"(?m)^\s+[^#]I?dentityAgent\s.+?1password-agent-proxy\.sock$"

type SSHConfigStatus* = enum
  PROXY_INSTALLED = 0  # our proxy is installed
  AGENT_INSTALLED = 1  # original 1p agent is installed
  NOT_INSTALLED = 2  # no agent found in config

template debugLog(msg: string) =
  if DEBUG:
    echo "[DEBUG] " & msg


proc getInstallTarget*(): string =
  return joinPath(expandTilde(INSTALL_PATH), getAppFilename().extractFilename())

proc copyBin*(target: string): bool =
  let path = getEnv("PATH").split(":").map(expandTilde)

  if target.splitFile()[0] notin path:
    echo fmt"WARNING: {target} is not in PATH."

  try:
    for p in target.parentDirs(inclusive=false):
      if not existsOrCreateDir(p):
        echo fmt"Creating directory: {p}"
    
    debugLog "Copying executable..."
    copyFile(getAppFilename(), target)

    debugLog "Ensuring executable permissions..."
    setFilePermissions(target, getFilePermissions(target) + {fpUserExec})
  except OSError:
    return false

  return true


proc checkSSHAlias*(): bool =
  let cur = findExe("ssh", followSymlinks=false)
  try:
    discard expandSymlink(cur)
    return true
  except OSError:
    # not a symlink (yet)
    return false


proc aliasSSH*(bin: string): bool =
  let target = joinPath(expandTilde(INSTALL_PATH), "ssh")
  try:
    for p in target.parentDirs(inclusive=false):
      if not existsOrCreateDir(p):
        echo fmt"Creating directory: {p}"
    
    createSymlink(bin, target)
  except OSError:
    return false
  
  return true


proc writeSystemdService*(bin: string): bool =
  debugLog "Writing service file..."
  let f = open(expandTilde(SYSTEMD_SERVICE_PATH), mode=fmWrite)
  f.write(SYSTEMD_SERVICE.fmt)
  f.close()

  debugLog "Enabling service..."
  if execCmd(SYSTEMD_ENABLE_CMD) != 0:
    return false

  debugLog "Starting service..."
  if execCmd(SYSTEMD_START_CMD) != 0:
    return false

  return true


proc checkSSHAgentStatus*(): SSHConfigStatus =
  var data = ""

  try:
    let f = open(expandTilde(SSH_CONF_PATH))
    data = f.readAll()
    f.close()
  except OSError:
    return SSHConfigStatus.NOT_INSTALLED

  if data.contains(AGENT_SOCK_PROXY_RE):
    return SSHConfigStatus.PROXY_INSTALLED
  elif data.contains(AGENT_SOCK_1P_RE):
    return SSHConfigStatus.AGENT_INSTALLED
  return SSHConfigStatus.NOT_INSTALLED


proc updateSSHConfig*(status: SSHConfigStatus, proxyPath: string): bool =
  if status == SSHConfigStatus.PROXY_INSTALLED:
    return true

  var content: string
  try:
    let f = open(expandTilde(SSH_CONF_PATH))
    content = f.readAll()
    f.close()
  except OSError:
    return false

  if status == SSHConfigStatus.NOT_INSTALLED:
    content &= "\n" & fmt"""
    Host *
        IdentityAgent {proxyPath}
    """.dedent
  elif status == SSHConfigStatus.AGENT_INSTALLED:
    content = content.replace(AGENT_SOCK_1P_RE, fmt"    IdentityAgent {proxyPath}")
  
  try:
    let f = open(expandTilde(SSH_CONF_PATH), mode=fmWrite)
    f.write(content)
    f.close()
  except OSError:
    return false

  return true
