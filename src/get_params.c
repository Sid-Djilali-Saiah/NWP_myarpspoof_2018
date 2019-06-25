/*
** EPITECH PROJECT, 2022
** NWP_myarpspoof_2018
** File description:
** Created by sid,
*/

#include <ifaddrs.h>
#include "myarpspoof.h"

unsigned char *convert_mac_addr(char *mac_str)
{
    unsigned char *mac;
    int values[6];

    for (int i = 0; mac_str[i]; i++)
        mac_str[i] = (char)tolower(mac_str[i]);
    mac = (unsigned char *)str_malloc(ETH_ALEN);
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x%*c",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5]) != 6)
    {
        perror("sscanf()");
        exit(FAILURE);
    }
    for (int i = 0; i < 6; ++i )
        mac[i] = (unsigned char)values[i];
    return (mac);
}

void get_if_hwaddr(char *interface, t_params *params)
{
    char *mac;
    char file_name[64];
    FILE *fp;
    size_t size = 32;
    ssize_t ret = 0;

    mac = str_malloc((int)size);
    strcpy(file_name, "/sys/class/net/");
    strcat(file_name, interface);
    strcat(file_name, "/address");
    fp = fopen(file_name, "r");
    if (fp == NULL)
        exit(FAILURE);
    ret = getline(&mac, &size, fp);
    if (ret == -1)
        exit(FAILURE);
    mac[strlen(mac) - 1] = '\0';
    params->source_mac = convert_mac_addr(mac);
    fclose(fp);
}

void get_iface_info(char **argv, t_params *params)
{
    if (strlen(argv[3]) > (IFNAMSIZ - 1)) {
        printf("Error : invalid interface name");
        exit(FAILURE);
    }
    params->interface = str_malloc(IFNAMSIZ);
    strcpy(params->interface, argv[3]);
    params->iface_idx = if_nametoindex(params->interface);
    if (params->iface_idx == 0)
    {
        perror("if_nametoindex()");
        exit(FAILURE);
    }
    get_if_hwaddr(params->interface, params);
}

void    get_source_ip(char **argv, t_params *params)
{
    char *source_ip;
    int  status;

    source_ip = str_malloc(INET_ADDRSTRLEN);
    strcpy(source_ip, argv[1]);
    status = inet_pton(AF_INET, source_ip, &params->source_ip);
    if (status != 1) {
        printf("Error inet_pton() : invalid source ip address");
        exit(FAILURE);
    }
}

void	get_victim_ip(char **argv, t_params *params)
{
    int                     status;
    struct addrinfo         hints, *res;
    struct sockaddr_in      *in_addr;

    params->victim_str_ip = str_malloc(INET_ADDRSTRLEN);
    strcpy(params->victim_str_ip, argv[2]);
    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    status = getaddrinfo(params->victim_str_ip, NULL, &hints, &res);
    if (status != 0) {
        printf ("Error getaddrinfo() : invalid victim ip address");
        exit(FAILURE);
    }
    in_addr = (struct sockaddr_in *)res->ai_addr;
    memcpy(&params->victim_ip, &in_addr->sin_addr, sizeof(uint32_t));
    freeaddrinfo(res);
}