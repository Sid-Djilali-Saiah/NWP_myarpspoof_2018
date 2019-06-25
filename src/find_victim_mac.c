/*
** EPITECH PROJECT, 2022
** NWP_myarpspoof_2018
** File description:
** Created by sid,
*/

#include "myarpspoof.h"

void    update_my_ip(t_params *params)
{
    uint32_t ip;
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , params->interface , IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    ip = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));
    params->broadcast_ip = ip;
}

unsigned char       *create_request_packet(t_params *params)
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
    memcpy(arp_hdr->sender_ip, &params->broadcast_ip, sizeof(uint32_t));
    memcpy(arp_hdr->sender_mac, params->source_mac, ETH_ALEN);
    memcpy(arp_hdr->target_ip, &params->victim_ip, sizeof(uint32_t));
    memset(arp_hdr->target_mac, 0xff, ETH_ALEN);
    return (packet);
}

void    send_arp_request(t_params *params)
{
    struct sockaddr_ll addr;
    unsigned char *request_packet;
    ssize_t nbytes;

    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = params->iface_idx;
    addr.sll_hatype = htons(ARPHRD_ETHER);
    addr.sll_pkttype = PACKET_BROADCAST;
    addr.sll_halen = ETH_ALEN;
    memcpy(&addr.sll_addr, params->source_mac, 6 * sizeof(unsigned char));
    update_my_ip(params);
    request_packet = create_request_packet(params);
    nbytes = sendto(params->socket_fd, request_packet, 42, 0,
        (struct sockaddr *)&addr, sizeof(addr));
    if (nbytes == -1)
    {
        perror("sendto()");
        exit(FAILURE);
    }
}

bool    handle_arp_reply(unsigned char *packet, t_params *params)
{
    t_arphdr        *arp_hdr;
    struct ethhdr   *eth_hdr;

    eth_hdr = (struct ethhdr *)packet;
    arp_hdr = (struct s_arphdr *)(packet + ETHERNET_HDRLEN);
    if (ntohs(eth_hdr->h_proto) != ETH_P_ARP) {
        free(packet);
        return (false);
    }
    if (ntohs(arp_hdr->opcode) != 0x02) {
        free(packet);
        return (false);
    }
    params->victim_mac = (unsigned char *)str_malloc(ETH_ALEN);
    memcpy(params->victim_mac, arp_hdr->sender_mac, ETH_ALEN);
    print_victim_mac(params->victim_mac);
    return (true);
}

bool    receive_arp_reply(t_params *params)
{
    ssize_t         nbytes;
    unsigned char   *reply_packet;

    reply_packet = (unsigned char *)str_malloc(PACKET_LEN);
    nbytes = recvfrom(params->socket_fd, reply_packet, PACKET_LEN,
                        0, NULL, NULL);
    if (nbytes == -1) {
        perror("recvfrom()");
        exit(FAILURE);
    }
    if (handle_arp_reply(reply_packet, params) == false)
        return (false);
    free(reply_packet);
    return (true);
}