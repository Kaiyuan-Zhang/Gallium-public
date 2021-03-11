

// +---------------+         +---------------+
// |      s1       |         |       s2      |
// |               |         |               |
// | 192.168.1.1   |         | 192.168.1.2   |
// |               |         |               |
// | 192.168.1.100 |         |               |
// | (fake server) |         |(actual server)|
// |               |         |               |
// | (fake client) |         |               |
// +---------------+         +---------------+

// 192.168.1.1 : fake client addr
// 192.168.1.100 : fake server addr

AddressInfo(
    s1      10.25.1.10  255.255.255.0/24  aa:aa:aa:aa:aa:aa,
    s2      10.25.1.16  255.255.255.0/24  bb:bb:bb:bb:bb:bb,
    mb      10.25.1.4   255.255.255.0/24  cc:cc:cc:cc:cc:cc
);

ip_class :: Classifier(12/0800, -);

src_dst_class :: Classifier(6/aaaaaaaaaaaa, -);
to_s1 :: EtherEncap(0x0800, mb, s1);
to_s2 :: EtherEncap(0x0800, mb, s2);
out :: ToDPDKDevice(4);

//print0 :: Print(LABEL "input", MAXLENGTH 60);

FromDPDKDevice(4)
-> ip_class
-> src_dst_class
-> Strip(14)
-> to_s2;

ip_class[1] -> Discard;
src_dst_class[1] -> Strip(14) -> to_s1;

to_s1 -> out;
to_s2 -> out;
