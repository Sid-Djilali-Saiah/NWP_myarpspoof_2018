/*
** EPITECH PROJECT, 2022
** NWP_myarpspoof_2018
** File description:
** Created by sid,
*/

#include "myarpspoof.h"

void	usage(char *program)
{
    printf("Usage :\n\t1 %s <source_ip> <victim_ip> <iface>"
        " (must be root)\n"
        "\t2 ./myarpspoof <source_ip> <victim_ip> <iface>"
        " --printBroadcast\n"
        "\t3 ./myarpspoof <source_ip> <victim_ip> <iface>"
        " --printSpoof [MAC addr]\n", program);
    exit(FAILURE);
}

void    create_bind_socket(t_params *params)
{
    struct sockaddr_ll sll;

    params->socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (params->socket_fd < 1)
    {
        perror("socket()");
        exit(FAILURE);
    }
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = params->iface_idx;
    if (bind(params->socket_fd, (struct sockaddr*)&sll,
        sizeof(struct sockaddr_ll)) < 0)
    {
        perror("bind()");
        close(params->socket_fd);
        exit(FAILURE);
    }
}

void    print_victim_mac(unsigned char *mac)
{
    printf("Found victim's MAC address: '");
    for (int i = 0; i < 5; i++)
    {
        printf ("%02x:", mac[i]);
    }
    printf("%02x", mac[5]);
    printf("'\n");
}

char        *str_malloc(int size)
{
    char    *str;

    if (size <= 0)
    {
        printf("Error str_malloc() : invalid size.");
        exit(FAILURE);
    }
    str = malloc(sizeof(char) * size);
    if (str == NULL)
    {
        printf("Error str_malloc() : cannot allocate memory.");
        exit(FAILURE);
    }
    memset(str, 0, sizeof(char) * size);
    return (str);
}