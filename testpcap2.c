#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){
  static int count = 1;
  fprintf(stdout, "%d, ", count);
  if (count == 4) {
    fprintf(stdout, "Come on baby sayyy you love me");
  }
  if (count == 7) {
    fprintf(stdout, "Times");
  }
  fflush(stdout);
  count++;
}

int main(int argc, char **argv) {
  int i;
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
  const u_char *packet;
  struct ether_header *epter;

  if (argc != 2) { fprintf(stdout,"Usage: %s numpackets\n",argv[0]);return 0;}

  /*grab a device*/
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    printf("%s\n", errbuf);
    exit(1);
  }

  /* open device for reading */
  descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
  if (descr == NULL) {
    printf("pcap_open_live(): %s\n",errbuf); exit(1);
  }

  pcap_loop(descr, atoi(argv[1]), my_callback, NULL);

  fprintf(stdout, "\nDone processing packets... wheew!\n");
  return 0;
}