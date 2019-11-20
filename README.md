# evilDNS
Evil DNS server
===============

```
Usage:


cmd1.cmd2.(...).cmdN.your.domain.tld

Where: opcode:
  functionName-param1-param2-param3...


Available functions:
 xss(recordType, payloadID)
  recordType = any DNS record type
  payloadId = ['r', 'a', <int>]
  -> return record w/ XSS from payload list

 sqli(recordType, payloadID)
  recordType = any DNS record type
  payloadId = ['r', 'a', <int>]
  -> return record w/ SQLi from payload list

 ans(recordType, data, dot=":")
  recordType = any DNS record type
  data = data for record (in valid format!)
  dot = character that will be replaced w/ dot "."
  -> return record w/ specified value

 dec(recordType, value, encoding="hex")
  recordType = any DNS record type
  value = encoded data
  encoding = encoding type. Supported: [hex, b64]
  -> return record w/ specified decoded value

 cloop(nonce=None)
  nonce - random nonce. regenerated in query. Optional
  -> return NS record that loops

 setrr(sectionName):
  sectionName = ["ans", "add", "aut" ]
  -> adds NO record
  -> sets RR section that following records will be put in



```

