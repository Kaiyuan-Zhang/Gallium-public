// mazu-nat.click

// This configuration is the lion's share of a firewalling NAT gateway. A
// version of this configuration was in daily use at Mazu Networks, Inc.
//
// Mazu was hooked up to the Internet via a single Ethernet connection (a
// cable modem). This configuration ran on a gateway machine hooked up
// to that cable modem via one Ethernet card. A second Ethernet card was
// hooked up to our internal network. Machines inside the internal network
// were given internal IP addresses in net 10.
//
// Here is a network diagram. Names in starred boxes must have addresses
// specified in AddressInfo. (No bare IP addresses occur in this
// configuration; everything has been specified through AddressInfo.)
//
//     +---------+
//    /           \                                              +-------
//   |             |       +-----------+           +-------+    /        
//   |  internal   |   ********     ********   **********  |   |         
//   |  network    |===*intern*     *extern*===*extern_ *  |===| outside 
//   |             |===*      *     *      *===*next_hop*  |===|  world  
//   |  *********  |   ********     ********   **********  |   |         
//   |  *intern_*  |       |  GATEWAY  |           | MODEM |    \        
//   |  *server *  |       +-----------+           +-------+     +-------
//    \ ********* /
//     +---------+
//
// The gateway supported the following functions:
//
// - Forwards arbitrary connections from the internal network to the outside
//   world.
// - Allows arbitrary FTP connections from the internal network to the outside
//   world. This requires application-level packet rewriting to support FTP's
//   PASV command. See FTPPortMapper, below.
// - New HTTP, HTTPS, and SSH connections from the outside world are allowed,
//   but they are forwarded to the internal machine `intern_server'.
// - All other packets from the outside world are sent to the gateway's Linux
//   stack, where they are handled appropriately.
//
// The heart of this configuration is the IPRewriter element and associated
// TCPRewriter and IPRewriterPatterns elements. You should probably look at
// the documentation for IPRewriter before trying to understand the
// configuration in depth.
//
// Note that the configuration will only forward TCP and UDP through the
// firewall. ICMP is not passed. A nice exercise: Add ICMP support to the
// configuration using the ICMPRewriter and ICMPPingRewriter elements.
//
// See also thomer-nat.click


// ADDRESS INFORMATION

AddressInfo(
  intern 	192.168.1.1	0.255.255.0/8		3c:fd:fe:9e:5d:01,
  extern	192.168.1.1	255.255.255.0/24	3c:fd:fe:9e:7d:21,
  extern_next_hop					3c:fd:fe:9e:5d:01,
  intern_server	10.0.0.10
);

AddressInfo (
       my_ens2d1 10.101.0.13 255.255.255.0/24 00:02:c9:a5:c8:82,
       my_ens2   10.101.1.13 255.255.255.0/24 00:02:c9:a5:c8:81,
       ens2d1    10.101.0.16 255.255.255.0/24 00:02:c9:a4:37:f2,
       ens2      10.101.1.16 255.255.255.0/24 00:02:c9:a4:37:f1
);


// DEVICE SETUP

elementclass GatewayDevice {
  $device |
  from :: FromDPDKDevice($device)
	-> output;
  input -> to :: ToDPDKDevice($device);
  ScheduleInfo(from .1, to 1);
}

//source :: FromDPDKDevice(0);
//sink :: ToDPDKDevice(0);

extern_dev :: GatewayDevice(2); // ens2
intern_dev :: GatewayDevice(3); // ens2d1

// extern_dev :: Print(MAXLENGTH 60, ACTIVE false);
// intern_dev :: Print(MAXLENGTH 60, ACTIVE false);

to_extern :: Print(LABEL "to_ext", MAXLENGTH 60, ACTIVE false);
to_intern :: Print(LABEL "to_int", MAXLENGTH 60, ACTIVE false);

// compat_rewriter :: IPRewriter(pattern - - 192.168.1.2 - 0 0,
                              // pattern 192.168.1.100 - - - 1 1);

compat_rw :: IPRewriter(pattern - - ens2 - 0 0)
                        //pattern - - - - 1 1);

// my_class :: IPClassifier(dst host 192.168.1.1, -);

// source -> Classifier(12/0800) -> Strip(14) -> CheckIPHeader
// -> my_class
//-> Print(LABEL "from ext 00")
// -> [1] compat_rewriter [1]
//-> Print(LABEL "from ext 01")
// -> EtherEncap(0x0800, 3c:fd:fe:9e:5d:01, 3c:fd:fe:9e:7d:21)
// -> extern_dev;

// my_class[1] -> EtherEncap(0x0800, 3c:fd:fe:9e:5d:01, 3c:fd:fe:9e:7d:21) -> intern_dev;

// ip_sink :: EtherEncap(0x0800, 3c:fd:fe:9e:7d:21, 3c:fd:fe:9e:5d:01) -> sink;

to_extern -> Strip(14) -> CheckIPHeader -> [0]compat_rw[0] 
-> EtherEncap(0x0800, my_ens2, ens2) -> extern_dev; 
// -> Strip(14) -> CheckIPHeader -> [0] compat_rewriter [0] -> ip_sink;
to_intern -> Strip(14) -> EtherEncap(0x0800, my_ens2d1, ens2d1) -> intern_dev; 
// -> Strip(14) -> CheckIPHeader -> ip_sink;

// extern_w_encap :: EtherEncap(0x0800, 3c:fd:fe:9e:7d:21, 3c:fd:fe:9e:5d:01)
// -> extern_dev;

// intern_w_encap :: EtherEncap(0x0800, 3c:fd:fe:9e:7d:21, 3c:fd:fe:9e:5d:01)
// -> intern_dev;

ip_to_host :: EtherEncap(0x0800, 1:1:1:1:1:1, intern)
	-> Discard;


// ARP MACHINERY

extern_arp_class, intern_arp_class
	:: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
//intern_arpq :: ARPQuerier(intern);

extern_dev
-> Strip(14) -> CheckIPHeader -> IPRewriter(pattern my_ens2d1 - - - 0 0)
-> EtherEncap(0x0800, ens2, my_ens2)
-> extern_arp_class;

//extern_dev -> extern_arp_class;
extern_arp_class[0] -> ARPResponder(extern)	// ARP queries
	-> to_extern;
extern_arp_class[1] -> Discard;			// ARP responses
extern_arp_class[3] -> Discard;

intern_dev -> intern_arp_class;
intern_arp_class[0] -> ARPResponder(intern)	// ARP queries
	-> to_intern;
intern_arp_class[1] -> intern_arpr_t :: Tee;
	intern_arpr_t[0] -> Discard;
	intern_arpr_t[1] -> Discard; // [1]intern_arpq;
intern_arp_class[3] -> Discard;


// REWRITERS

IPRewriterPatterns(to_world_pat my_ens2 50000-65535 - -,
                   to_server_pat intern 50000-65535 intern_server -);

rw :: VanillaIPRewriter(// internal traffic to outside world
	         pattern to_world_pat 0 1,
		 // external traffic redirected to 'intern_server'
		 pattern to_server_pat 1 0,
		 // internal traffic redirected to 'intern_server'
		 pattern to_server_pat 1 1,
		 // virtual wire to output 0 if no mapping
		 pass 0,
		 // virtual wire to output 2 if no mapping
		 pass 2);

tcp_rw :: TCPRewriter(// internal traffic to outside world
		pattern to_world_pat 0 1,
		// everything else is dropped
		drop);


// OUTPUT PATH

ip_to_extern :: GetIPAddress(16)
      -> CheckIPHeader
      -> EtherEncap(0x0800, extern:eth, extern_next_hop:eth)
      -> to_extern;
ip_to_intern :: GetIPAddress(16)
      -> CheckIPHeader
      //-> [0]intern_arpq
      -> EtherEncap(0x0800, extern:eth, extern_next_hop:eth)
      -> to_intern;


// to outside world or gateway from inside network
rw[0]
-> ip_to_extern_class :: IPClassifier(dst host intern, -);
  ip_to_extern_class[0] -> ip_to_host;
  ip_to_extern_class[1] -> ip_to_extern;
// to server
rw[1]
//-> Print(LABEL "to_int")
-> ip_to_intern;
// only accept packets from outside world to gateway
rw[2] -> IPClassifier(dst host extern) -> ip_to_host;

// tcp_rw is used only for FTP control traffic
tcp_rw[0] -> ip_to_extern;
tcp_rw[1] -> ip_to_intern;


// FILTER & REWRITE IP PACKETS FROM OUTSIDE

ip_from_extern :: IPClassifier(dst host my_ens2,
			-);
my_ip_from_extern :: IPClassifier(dst tcp ssh,
			dst tcp www or https,
			src tcp port ftp,
			tcp or udp,
			-);

extern_arp_class[2] -> Strip(14)
  	-> CheckIPHeader
	-> ip_from_extern;
ip_from_extern[0] -> my_ip_from_extern;
  my_ip_from_extern[0] -> [1]rw; // SSH traffic (rewrite to server)
  my_ip_from_extern[1] -> [1]rw; // HTTP(S) traffic (rewrite to server)
  my_ip_from_extern[2] -> [1]tcp_rw; // FTP control traffic, rewrite w/tcp_rw
  my_ip_from_extern[3]
  // -> Print(LABEL "from_ext", MAXLENGTH 60)
  -> [4]rw; // other TCP or UDP traffic, rewrite or to gw
  my_ip_from_extern[4] -> Discard; // non TCP or UDP traffic is dropped
ip_from_extern[1] -> Discard;	// stuff for other people


// FILTER & REWRITE IP PACKETS FROM INSIDE

ip_from_intern :: IPClassifier(dst host intern,
			dst net intern,
			dst tcp port ftp,
			-);
my_ip_from_intern :: IPClassifier(dst tcp ssh,
			dst tcp www or https,
			src or dst port dns,
			dst tcp port auth,
			tcp or udp,
			-);

intern_arp_class[2] -> Strip(14)
  	-> CheckIPHeader
	-> ip_from_intern;
ip_from_intern[0] -> my_ip_from_intern; // stuff for 10.0.0.1 from inside
  my_ip_from_intern[0] -> ip_to_host; // SSH traffic to gw
  my_ip_from_intern[1] -> [2]rw; // HTTP(S) traffic, redirect to server instead
  my_ip_from_intern[2] -> Discard;  // DNS (no DNS allowed yet)
  my_ip_from_intern[3] -> ip_to_host; // auth traffic, gw will reject it
  my_ip_from_intern[4] -> [3]rw; // other TCP or UDP traffic, send to linux
                             	// but pass it thru rw in case it is the
				// returning redirect HTTP traffic from server
  my_ip_from_intern[5] -> ip_to_host; // non TCP or UDP traffic, to linux
ip_from_intern[1] -> ip_to_host; // other net 10 stuff, like broadcasts
ip_from_intern[2] -> FTPPortMapper(tcp_rw, rw, 0)
		-> [0]tcp_rw;	// FTP traffic for outside needs special
				// treatment
ip_from_intern[3] -> [0]rw;	// stuff for outside
