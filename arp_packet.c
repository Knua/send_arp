#include <stdint.h>
#include <stdlib.h>
#include "arp_packet.h"

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

arp_packet * arp_request_get_sender_mac_addr
(uint8_t * src_mac, uint8_t * dst_ip){ // dst_mac 을 모르는 상황

    arp_packet * send_packet = malloc(sizeof(arp_packet));

    copy_6byte_by_one_bit(0xff, (* send_packet).destination_mac_address);
    copy_6byte(src_mac, (* send_packet).source_mac_address);
    (* send_packet).ethertype = Ethertype_ARP;
    (* send_packet).hardware_type = ARP_hardware_type_Ethernet;
    (* send_packet).protocol_type = Ethertype_IPv4;
    (* send_packet).hardware_length = MAC_address_length;
    (* send_packet).protocol_length = IPv4_address_length;
    (* send_packet).operation = ARP_operation_request;
    copy_6byte(src_mac, (* send_packet).sender_hardware_address);
    copy_4byte_by_one_bit(0x00, (* send_packet).sender_protocol_address);
    copy_6byte_by_one_bit(0x00, (* send_packet).target_hardware_address);
    copy_4byte(dst_ip, (* send_packet).target_protocol_address);
    
    return send_packet;
}