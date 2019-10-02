#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "arp_packet.h"

void ip_str_to_addr(char * str, uint8_t * addr){
    int nowNum = 0, nowidx = 0;
    int str_len = strlen(str);
    for(int i = 0; i < str_len; i++){
        if(str[i] == '.'){
            addr[nowidx++] = nowNum;
            nowNum = 0;
            continue;
        }
        nowNum *= 10;
        nowNum += str[i] - '0';
    }
    addr[nowidx] = nowNum; // x.y.z.k 에서 k는 이 순간 저장
}

void copy_6byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 6; i++){
        dst[i] = src[i];
    }
}
void copy_4byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 4; i++){
        dst[i] = src[i];
    }
}
void copy_6byte_by_one_bit(uint8_t bit, uint8_t * dst){
    for(int i = 0; i < 6; i++){
        dst[i] = bit;
    }
}
void copy_4byte_by_one_bit(uint8_t bit, uint8_t * dst){
    for(int i = 0; i < 4; i++){
        dst[i] = bit;
    }
}

arp_packet arp_request_get_sender_mac_addr
(uint8_t * src_mac, uint8_t * dst_ip){ // dst_mac 을 모르는 상황
    arp_packet send_packet;

    copy_6byte_by_one_bit(0xff, send_packet.destination_mac_address);
    copy_6byte(src_mac, send_packet.source_mac_address);
    send_packet.ethertype = htons(Ethertype_ARP); // 2byte
    send_packet.hardware_type = htons(ARP_hardware_type_Ethernet); // 2byte
    send_packet.protocol_type = htons(Ethertype_IPv4); // 2byte
    send_packet.hardware_length = MAC_address_length; // 1byte
    send_packet.protocol_length = IPv4_address_length; // 1byte
    send_packet.operation = htons(ARP_operation_request); // 2byte
    copy_6byte(src_mac, send_packet.sender_hardware_address);
    copy_4byte_by_one_bit(0x00, send_packet.sender_protocol_address);
    copy_6byte_by_one_bit(0x00, send_packet.target_hardware_address);
    copy_4byte(dst_ip, send_packet.target_protocol_address);
    
    return send_packet;
}