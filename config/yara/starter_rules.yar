rule MAYA_EXT_RANSOMWARE {
  strings:
    $a = "your files have been encrypted"
    $b = "pay bitcoin"
    $c = "decryptor"
  condition:
    2 of them
}

rule MAYA_EXT_CRED_DUMP {
  strings:
    $a = "mimikatz"
    $b = "lsass"
    $c = "sekurlsa::"
  condition:
    2 of them
}

rule MAYA_EXT_PROCESS_INJECT {
  strings:
    $a = "CreateRemoteThread"
    $b = "WriteProcessMemory"
    $c = "VirtualAllocEx"
  condition:
    2 of them
}

rule MAYA_EXT_BEACONING {
  strings:
    $a = "beacon"
    $b = "command-and-control"
    $c = "C2"
  condition:
    2 of them
}
