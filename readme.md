http://yuba.stanford.edu/~casado/pcap/section2.html

在命令行中ping baidu.com，然后执行a.out，可以看到

```
DEV: eno1
Grabbed packet of length 98
Recieved at ..... Tue Aug 20 09:55:17 2019

Ethernet address length is 14
Ethernet type hex:800 dec:2048 is an IP packet
 Destination Address:   54:75:95:4f:77:df
 Source Address:   70:85:c2:61:29:5b
```

这个source Address就是这台机器的地址，而 Destination Address是目标机器的地址，当然，这不是百度的服务器的mac地址，而是网络包的下一跳的mac地址，一般来说就是路由器的地址啦

```
> route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         _gateway        0.0.0.0         UG    100    0        0 eno1
link-local      0.0.0.0         255.255.0.0     U     1000   0        0 eno1
192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 eno1

> arp
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.103            ether   4c:32:75:9b:bf:7d   C                     eno1
192.168.1.102            ether   4c:32:75:99:a8:99   C                     eno1
_gateway                 ether   54:75:95:4f:77:df   C                     eno1
```

确认了，确实是发给了gateway。

The point is this, in order for your computer to send the packet it must first get the MAC address of the next hop.

But how my computer know the gateway hardware address?

My computer know the ip address of the gateway.这里是192.168.1.1

Hardware addresses on ethernet are obtained using the Address Resolution Protocol or ARP. ARP is is described in RFC826.

ETHERTYPE_ARP is defined in net/ethernet.h

```
#define ETHERTYPE_ARP      0x0806
```

你可以通过手动清除电脑的ARP cache来强制触发ARP Request.

```
arp -n  # look at arp cache
arp -n -d 192.168.1.103   # 删除一个arp项
arp -n 
```

## pcap bpf

```
pcap_lookupdev  查询device
pcap_open_live  打开device
pcap_loop       read packets from a pcap_t until an interrupt or error occurs
pcap_dispatch   read a bufferful of packets from a pcap_t open for a live capture or the full set of packets from a pcap_t open for a savefile.
```

pcap_dispatch() is used to collect and process packets. cnt specifies the maximum number of packets to process before returning. A cnt of -1 processes all the packets received in one buffer. A cnt of 0 processes all packets until an error occurs, EOF is reached, or the read times out (when doing live reads and a non-zero read timeout is specified). callback specifies a routine to be called with three arguments: a u_char pointer which is passed in from pcap_dispatch(), a pointer to the pcap_pkthdr struct (which precede the actual network headers and data), and a u_char pointer to the packet data. The number of packets read is returned. Zero is returned when EOF is reached in a ``savefile.'' A return of -1 indicates an error in which case pcap_perror() or pcap_geterr() may be used to display the error text. 

很多时候我们抓包，并不是对所有的包都感兴趣。这时候可以使用pcap_compile()和pcap_setfilter()


