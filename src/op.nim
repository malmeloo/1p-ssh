import osproc, json, strutils, sets

# command to get all SSH keys from the user's 1Password vault
const OP_COMMAND = "op item list --categories SSHKey --format=json --cache | op item get - --format=json --cache"
const MAX_RETRIES = 2


type
  SavedKey* = object
    fingerprint*: string
    hosts*: HashSet[string]


proc parseKeys(buf: string): seq[JsonNode] =
  # the command returns multiple JSON objects, so we first need
  # to split them into separate strings containing these objects
  var objects: seq[string] = @[""]
  var objCounter = 0
  for character in buf:
    if character == '{':
      objCounter += 1
    elif character == '}':
      objCounter -= 1

    objects[^1].add(character)
    if objCounter == 0:
      objects[^1] = objects[^1].strip
      if objects[^1].len > 0:
        objects.add("")
  
  for obj in objects:
    if obj.len == 0:
      continue
    result.add(parseJson(obj))


proc getKeys*(): seq[SavedKey] =
  echo "Getting key data from vault"

  var retries = 1
  var success = false
  var output: string
  while not success:
    if retries > MAX_RETRIES:
      raise newException(CatchableError, "Unable to use 1p CLI: " & output)

    let res = execCmdEx(OP_COMMAND)
    output = res.output
    success = res.exitCode == 0 and not output.startsWith "[ERROR]"

    if not success:
      echo "Retry: " & $retries
      retries += 1

  let itemNodes = parseKeys(output)
  for node in itemNodes:
    result.add(SavedKey())

    let fields = node["fields"]
    for field in fields:
      if field["id"].getStr() == "fingerprint":
        result[^1].fingerprint = field["value"].getStr()
      elif field["label"].getStr() == "host":
        result[^1].hosts.incl(field["value"].getStr())
