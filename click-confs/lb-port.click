ip_class :: Classifier(12/0800, -);
ip_addr_class :: IPClassifier(dst host 192.168.1.100, // client to server
	      	 	      dst host 192.168.1.1,   // reply from server
			      -);

// src_rewriter :: IPRewriter(pattern 192.168.1.100 - - - 0 0,
// 	                   pattern 192.168.1.1 - - - 1 1);

rev_rewriter :: IPRewriter(pattern 192.168.1.100 - 192.168.1.2 - 0 0);
                           //pattern 192.168.1.2 - 132.168.1.100 - 1 1);

nat_rewriter :: IPRewriter(pattern 192.168.1.1 - 192.168.1.2 - 0 0);
                           //pattern 192.168.1.100 - 192.168.1.2 - 1 1);


ip_exit :: EtherEncap(0x0800, 3c:fd:fe:9e:7d:21, 3c:fd:fe:9e:5d:01);
ip_exit -> ToDPDKDevice(0);

cache :: VanillaIPRewriter(
           pattern - - - 5001 0 1,
		   pattern - - - 5002 0 1,
		   pattern - - - 5003 0 1,
		   pattern - - - 5004 0 1,
		   pass 2, 
		   pass 1);

rr :: RoundRobinSwitch;

FromDPDKDevice(0)
-> ip_class
-> Strip(14)
-> CheckIPHeader
-> ip_addr_class
-> [4]cache[2]
-> rr;

rr[0]
//-> Print(LABEL "rr0", MAXLENGTH 60)
-> [0]cache;

rr[1]
//-> Print(LABEL "rr1", MAXLENGTH 60)
-> [1]cache;

rr[2]
//-> Print(LABEL "rr2", MAXLENGTH 60)
-> [2]cache;

rr[3]
//-> Print(LABEL "rr3", MAXLENGTH 60)
-> [3]cache;

nat_rewriter[0] -> ip_exit;

ip_addr_class[1]
-> rev_rewriter
//-> IPRewriter(pattern - 8080 - - 0 0)
-> [5]cache[1]
-> ip_exit;

cache[0]
-> [0]nat_rewriter;

ip_class[1] -> Discard;
ip_addr_class[2] -> Discard;
