from dnslib.bit import get_bits,set_bits
import dnslib.dns

MAX_LABEL_LEN = 200

class HackedLabelBuffer(dnslib.dns.DNSBuffer):
    def encode_name(self,name):
        """
            Encode label and store at end of buffer (compressing
            cached elements where needed) and store elements
            in 'names' dict
        """
        #print("Hackable label decoder in place")
        if not isinstance(name,dnslib.dns.DNSLabel):
            name = dnslib.dns.DNSLabel(name)
        if len(name) > 253:
            raise dnslib.dns.DNSLabelError("Domain label too long: %r" % name)
        name = list(name.label)
        while name:
            if tuple(name) in self.names:
                # Cached - set pointer
                pointer = self.names[tuple(name)]
                pointer = set_bits(pointer,3,14,2)
                self.pack("!H",pointer)
                return
            else:
                self.names[tuple(name)] = self.offset
                element = name.pop(0)
                if len(element) > MAX_LABEL_LEN:
                    raise dnslib.dns.DNSLabelError("Label component too long: %r" % element)
                self.pack("!B",len(element))
                self.append(element)
        self.append(b'\x00')