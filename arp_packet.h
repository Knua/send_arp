#pragma once
#include <stdint.h>

#define ETHERTYPE 12
#define ETHERNET 14
#define ARP_OPCODE 20
#define ARP_SOURCE_MAC_ADDR 22
#define ARP_DESTINATION_MAC_ADDR 32
    // 가독성을 중시하여 이렇게 설정하였습니다만, 협업이 필요한 경우 반드시 수정이 필요하리라 예상됩니다.
#define ARP_PACKET_LEN 42
#define Ethertype_IPv4 0x0800
#define Ethertype_ARP  0x0806
#define ARP_hardware_type_Ethernet 1
#define MAC_address_length 6
#define IPv4_address_length 4
#define ARP_operation_request 1
#define ARP_operation_reply 2

void ip_str_to_addr(char * str, uint8_t * addr);
void copy_6byte(uint8_t * source, uint8_t * destination);
void copy_4byte(uint8_t * source, uint8_t * destination);
void copy_6byte_by_one_bit(uint8_t bit, uint8_t * dst);
void copy_4byte_by_one_bit(uint8_t bit, uint8_t * dst);

typedef struct _arp_packet {
    uint8_t destination_mac_address[6];
    uint8_t source_mac_address[6];
    uint16_t ethertype;
    // 여기서부터가 실질적인 arp packet
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_hardware_address[6];
    uint8_t sender_protocol_address[4];
    uint8_t target_hardware_address[6];
    uint8_t target_protocol_address[4];
} arp_packet; // 42byte

arp_packet arp_request_get_sender_mac_addr(uint8_t * attacker_mac, uint8_t * sender_ip);
arp_packet arp_reply_target_ip_with_attacker_mac(uint8_t * attacker_mac, uint8_t * sender_mac, uint8_t * target_ip, uint8_t * sender_ip);