import nativesockets, algorithm, sets
import ./op, ./proto

proc levenshtein(a, b: string): int =
  let n = a.len
  let m = b.len

  var dist = newSeq[int](m + 1)
  for i in 0 .. m: dist[i] = i
  
  var ind = 0
  var prevDiag = 0
  var prevAbove = 0
  for i in 0 ..< n:
    dist[0] = i + 1
    for j in 0 ..< m:
      ind = (if a[i] != b[j]: 1 else: 0)
      prevDiag = prevAbove
      prevAbove = dist[j + 1]
      dist[j + 1] = min([
        prevAbove + 1,
        dist[j] + 1,
        prevDiag + ind
      ])
  
  return dist[m]

proc hostScore(hosts: HashSet[string], cmpHost: string): float =
  result = 0
  for host in hosts:
    let maxLev = max(host.len, cmpHost.len)
    let score = 1 - (levenshtein(host, cmpHost) / maxLev)
    result = max(result, score)

proc keyScore(key: SavedKey, cmpHost: string): float =
  var resolvedHosts: HashSet[string]
  for host in key.hosts:
    for ip in getHostByName(host).addrList:
      if ip notin key.hosts:
        resolvedHosts.incl ip
  
  let resolvedScore = hostScore(resolvedHosts, cmpHost)
  let rawScore = hostScore(key.hosts, cmpHost)

  if rawScore > resolvedScore:
    # we boost the score a little when we match against the non-resolved
    # hosts because we want a key with "1.1.1.1" to score higher than
    # another key with "one.one.one.one" when the host to match is "1.1.1.1"
    return rawScore + 0.1
  return resolvedScore


proc sortKeys*(keys: var openArray[SavedKey], hostname: string) =
  keys.sort do (k1, k2: SavedKey) -> int:
    let s1 = keyScore(k1, hostname)
    let s2 = keyScore(k2, hostname)
    return cmp(s2, s1)


proc matchIdentities*(providedKeys: openArray[KeyIdentity],
                      savedKeys: openArray[SavedKey]): seq[KeyIdentity] =
  for sKey in savedKeys:
    for pKey in providedKeys:
      if sKey.fingerprint == pKey.kFp:
        result.add(pKey)
        break
    
  for pKey in providedKeys:
    if pKey notin result:
      result.add(pKey)
