#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

int main(int argc, char **argv)
{
  int i;
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *descr;
  const u_char *packet;
  struct pcap_pkthdr hdr;
  struct ether_header *eptr;

  u_char *ptr; /* printing out hardware header info */

  /* grab a device */
  dev = pcap_lookupdev(errbuf);

  if (dev == NULL)
  {
    printf("%s\n", errbuf);
    exit(1);
  }

  printf("DEV: %s\n", dev);

  /* open the device for sniffing
     pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)

     snaplen - maximum size of packets to capture in bytes.
     promisc - set card in promiscuous mode.(如果你开了淫乱模式，你就可以看到所有的网络包，不管是不是给你的)
     to_ms   - 开始读前等多少毫秒(等不到就time out)
     errbuf  - if something happens, place error string here.

     当 promisc 设置为非0的任意值时，你就开启了淫乱模式。
    */
  descr = pcap_open_live(dev, BUFSIZ, 0, 100, errbuf);

  if (descr == NULL)
  {
    printf("pcap_open_live(): %s\n", errbuf);
    exit(1);
  }

  /* grab a packet from descr
     u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
     pcap_pkthdr {
       struct timeval ts;         timestamp
       bpf_u_int32 caplen;        length of portion present
       bpf_u_int32;               length of this packet
     }
  */
  packet = pcap_next(descr, &hdr);
  if (packet == NULL)
  {
    printf("Didn't grab packet\n");
    exit(1);
  }
  printf("Grabbed packet of length %d\n", hdr.len);
  printf("Recieved at ..... %s\n", ctime((const time_t *)&hdr.ts.tv_sec));
  printf("Ethernet address length is %d\n", ETHER_HDR_LEN);

  /* lets start with the ether header...
  10Mb/s ethernet header
  struct ether_header{
    u_int8_t  ether_dhost[ETH_ALEN];	destination eth addr	
    u_int8_t  ether_shost[ETH_ALEN];	source ether addr
    u_int16_t ether_type;		          packet type ID field	
  } __attribute__ ((__packed__));
  */
  eptr = (struct ether_header *)packet;

  /* Do a couple of checks to see what packet type we have..*/
  if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
  {
    printf("Ethernet type hex:%x dec:%d is an IP packet\n",
           ntohs(eptr->ether_type),
           ntohs(eptr->ether_type));
  }
  else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
  {
    printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
           ntohs(eptr->ether_type),
           ntohs(eptr->ether_type));
  }
  else
  {
    printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
    exit(1);
  }

  /* copied from Steven's UNP */
  ptr = eptr->ether_dhost;
  i = ETHER_ADDR_LEN;
  printf(" Destination Address:  ");
  do
  {
    printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
  } while (--i > 0);
  printf("\n");

  ptr = eptr->ether_shost;
  i = ETHER_ADDR_LEN;
  printf(" Source Address:  ");
  do
  {
    printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
  } while (--i > 0);
  printf("\n");

  return 0;
}

// /* Ethernet protocol ID's */
// #define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
// #define	ETHERTYPE_IP		0x0800		/* IP */
// #define	ETHERTYPE_ARP		0x0806		/* Address resolution */
// #define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
