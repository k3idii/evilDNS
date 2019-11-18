# evilDNS
Evil DNS server


Usage:


cmd1.cmd2.(...).cmdN.your.domain.tld

Where: opcode:
  functionName-param1-param2-param3...


Available functions:
 xss(recordType, payloadID)
  recordType = any DNS record type
  payloadId = ['r', 'a', <int>]

 sqli(recordType, payloadID)
  recordType = any DNS record type
  payloadId = ['r', 'a', <int>]

 ans(recordType, data)
  recordType = any DNS record type
  data = data for record (in valid format!)

 cloop()
  return NS record that loops

 setrr(sectionName):
  sectionName = ["ans", "add", "aut" ]
  => sets RR section that following records will be put in



