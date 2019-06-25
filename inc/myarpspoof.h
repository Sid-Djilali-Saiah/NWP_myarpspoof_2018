/*
** EPITECH PROJECT, 2022
** NWP_myarpspoof_2018
** File description:
** Created by sid,
*/

#ifndef NWP_MYARPSPOOF_2018_MYARPSPOOF_H
#define NWP_MYARPSPOOF_2018_MYARPSPOOF_H

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdlib.h>
#include <net/if.h>
#include <netdb.h>
#include <memory.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#define SUCCESS 0
#define FAILURE 84
#define BROADCAST_PCKTLEN 42 /* sizeof(ethhdr) + sizeof(arphdr)*/
#define ETHERNET_HDRLEN 14
#define PACKET_LEN 64
#define IP_ALEN 4

typedef struct s_params
{
    char                *victim_str_ip;
    char                *victim_mac_str;
    unsigned char       *victim_mac;
    uint32_t            victim_ip;
    uint32_t            source_ip;
    uint32_t            broadcast_ip;
    unsigned char       *source_mac;
    char                *interface;
    int                 iface_idx;
    int                 socket_fd;
}               t_params;

typedef struct s_arphdr
{
    unsigned short  hardware_type;
    unsigned short  protocol_type;
    unsigned char   hardware_len;
    unsigned char   protocol_len;
    unsigned short  opcode;
    unsigned char   sender_mac[ETH_ALEN];
    unsigned char   sender_ip[IP_ALEN];
    unsigned char   target_mac[ETH_ALEN];
    unsigned char   target_ip[IP_ALEN];
}               t_arphdr;

void    get_source_ip(char **argv, t_params *params);
void	get_victim_ip(char **argv, t_params *params);
void    get_iface_info(char **argv, t_params *params);
void	usage();
char    *str_malloc(int size);
void    print_victim_mac(unsigned char *mac);
bool    valid_mac_address(char *mac);
unsigned char *convert_mac_addr(char *mac_str);
void    create_bind_socket(t_params *params);
unsigned char *create_broadcast_packet(t_params *params);
void    send_arp_request(t_params *params);
void    find_victim_mac(t_params *params);
void    send_spoofed_packets(t_params *params);
unsigned char *create_spoofed_packet(t_params *params);
void    myarpspoof(int argc, char **argv, t_params *params);
void    find_victim_mac(t_params *params);
bool    receive_arp_reply(t_params *params);
void    handle_args(int argc, char **argv, t_params *params);
void    create_bind_socket(t_params *params);

#endif /*!NWP_MYARPSPOOF_2018_MYARPSPOOF_H*/
