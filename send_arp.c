#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
// https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
// 에서 Jamesprite, Charles Salvia 의 코드를 참고하였습니다.

#include "arp_packet.h"
#include <pcap.h>
#include <stdint.h>
#define max(a,b) (a > b ? a : b) 
#define min(a,b) (a < b ? a : b) // 작성한 헤더

void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) 
{
// getting mac address 시작
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    uint8_t attacker_mac_address[6];
    if (success) memcpy(attacker_mac_address, ifr.ifr_hwaddr.sa_data, 6);
// getting mac address 끝

// 여기서부터 작성한 코드
    if (argc != 4){
        usage();
        return -1;
    }

    // uint8_t * attacker_mac_addres <- saves attacker(my) mac address
    char * dev       = argv[1];
    char * sender_ip = argv[2];
    char * target_ip = argv[3];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    // 첫 번째로 할 일 - sender 의 mac address 를 알아야 함
    arp_packet * arp_packet_get_sender_mac_packet;
    arp_packet_get_sender_mac_packet = arp_request_get_sender_mac_addr(attacker_mac_address, (uint8_t *)sender_ip);

    if(pcap_sendpacket(handle, (uint8_t *)arp_packet_get_sender_mac_packet, ARP_PACKET_LEN) != 0){
        printf("[Error] packet sending is failed.\n");
        return -1;
    }

    // 두 번째로 할 일 - sender 에게 [ip = target ip / mac = attacker mac] 인 arp response 전송
    

    return 0;
}