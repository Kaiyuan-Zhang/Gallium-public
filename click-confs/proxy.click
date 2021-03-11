// hacks for deployment

ip_class :: Classifier(12/0800, -);
ip_addr_class :: IPClassifier(dst host 192.168.1.100, // client to server
	      	 	      dst host 192.168.1.1,   // reply from server
			      -);

from_net :: Print(LABEL 'from_net', ACTIVE false, MAXLENGTH 60);
from_linux :: Print(LABEL 'from_linux', ACTIVE false, MAXLENGTH 60);

// src_rewriter :: IPRewriter(pattern 192.168.1.100 - - - 0 0,
// 	                   pattern 192.168.1.1 - - - 1 1);

// nat_rewriter :: IPRewriter(pattern - - 192.168.1.2 - 0 1,
//                            pattern - - 192.168.1.2 - 1 0);

FromDPDKDevice(0)
-> ip_class
-> Strip(14)
-> CheckIPHeader
-> ip_addr_class;

ip_class[1] -> Discard;
ip_addr_class[0] -> from_net;
ip_addr_class[1] -> from_linux;
ip_addr_class[2] -> Discard;

// Actual app

AddressInfo(
  FAKE  	192.168.1.1	0.255.255.0/8		3c:fd:fe:9e:5d:01,
  LOCAL     192.168.1.2     0.255.255.0/8           3c:fd:fe:9e:5d:01,
);

ip_exit :: EtherEncap(0x0800, 3c:fd:fe:9e:7d:21, 3c:fd:fe:9e:5d:01);
ip_exit -> ToDPDKDevice(0);

proxy_rw :: VanillaIPRewriter(pattern FAKE 1024-65535 LOCAL 8000 0 1,
                              drop);

other :: Discard;

from_net -> class:: IPClassifier(tcp and dst port 80,
                                 -);
class[1] -> other;

class[0] -> proxy_rw;

proxy_rw[0] -> ip_exit;

proxy_rw[1] -> ip_exit;

from_linux -> [1]proxy_rw;
