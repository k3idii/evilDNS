import sys
import dnslib.server
import dnslib
import payloads
import random
import string
import re
import base64

import hackedLabel


# install hacks 

dnslib.dns.DNSBuffer = hackedLabel.HackedLabelBuffer # overcome 64bytes limit ins req && repsp



logger = None

LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 53

FRENDLY_TLD = ".fake.in.0xe.ee"

DEFAULT_TTL = 1

KEYWORD_TO_RR_MAP = dict(
      ans = "add_answer",
      aut = "add_auth",
      add = "add_ar",
    )


def rand_from(src, size=10):
  return ''.join(random.choice(src) for _ in xrange(size))


def rand_az(size=10):
  return rand_from(string.ascii_lowercase, size)

def rand_hex(size=10):
  return rand_from(string.hexdigits, size)


def _ret(a,b):
  return dict(rtype=a, data=b)

def _common_handle_payload_list(ptr_list, rt, idx, prefix='', postfix=''):
  def _fix(s):
    return prefix + s.strip() + postfix

  if idx == 'a':
    return [ _ret(rt, _fix(x)) for x in ptr_list]
  if idx == 'r':
    idx = random.randint(0,len(ptr_list)-1)
  else:
    idx = int(idx) % len(ptr_list)
  return [ _ret(rt, _fix(ptr_list[idx])) ]

class TheQueryResponsePair(object):
  def __init__(self, req, rsp):
    self._req = req
    self._rsp = rsp
    self._qclass = self._req.q.qclass
    self._qname = str(req.q.qname)
    self.set_add_func()

  def set_add_func(self, name="add_answer"):
    self._curr_add_func_name = name
    self._add_func_ptr = getattr(self._rsp, self._curr_add_func_name, self._invalid_add_func)
    #print("SET PTR:" + str(self._add_func_ptr))

  def _invalid_add_func(self, *a, **kw):
    raise Exception("Invalid add function")

  def _fast_add_answer(self, rt, rd):
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
      if result is None:
        continue
      for entry in result:
        upper_rt = entry['rtype'].upper()
        rt_val = getattr(dnslib.QTYPE, upper_rt)
        rd_class = getattr(dnslib, upper_rt)
        self._add_func_ptr(dnslib.RR(
          rname = self._qname,
          ttl = DEFAULT_TTL,
          rclass = self._qclass,
          rtype = rt_val,
          rdata = rd_class(entry['data'])
        ))
        #self._fast_add_rr(rt_val, rd_class(entry['data']))

  def _handle_opt_ll(self, size=100):
    size = int(size)
    return [ _ret("CNAME", "x" * size + FRENDLY_TLD)  ]

  def _handle_opt_utf8(self, rt='txt', idx='r'):
    return _common_handle_payload_list(payloads.utf8s, rt, idx, prefix='utf', postfix='utf')

  def _handle_opt_xss(self, rt='txt', idx = 'r'):
    return _common_handle_payload_list(payloads.xss, rt, idx)

  def _handle_opt_sqli(self, rt='txt', idx = 'r'):
    return _common_handle_payload_list(payloads.sqli, rt, idx)  

  def _handle_opt_ans(self, rt='txt', val='ok', dot=':'):
    return [_ret(rt, val.replace(dot,"."))]

  def _handle_opt_dec(self, rt='txt', val='4141', code='hex'):
    if code == 'hex':
      val = base64.binascii.unhexlify(val)
    if code == 'b64':
      val = base64.b64decode(val)
    return [_ret(rt, val)]

  def _handle_opt_cloop(self, nonce=None):
    rv = self._qname
    new_val = 'cloop-' +rand_az(10)
    if nonce is None:
      rv = rv.replace('cloop',new_val)
    else:
      rv = re.sub('cloop-[a-z]+', new_val, rv)
    return [_ret('NS', rv)]

  def _handle_opt_setrr(self, rrname):
    new_func = KEYWORD_TO_RR_MAP.get(rrname, None)
    if new_func:
      self.set_add_func(new_func)

    



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
  global LISTEN_PORT
  if len(sys.argv) > 1:
    LISTEN_PORT = int(sys.argv[1])
  print("Will listen on {} : {} ".format(LISTEN_ADDR, LISTEN_PORT))
  resolver = MyResolver()
  logger = dnslib.server.DNSLogger(prefix=False)
  server = dnslib.server.DNSServer(resolver, port=LISTEN_PORT, address=LISTEN_ADDR, logger=logger)
  server.start()


if __name__ == "__main__":
  main()
else:
  print("This is MAIN module, you should run it !")
