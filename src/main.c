/*
** EPITECH PROJECT, 2022
** NWP_myarpspoof_2018
** File description:
** Created by sid,
*/

#include "myarpspoof.h"

void    handle_args(int argc, char **argv, t_params *params)
{
    if (argc < 4 || argc > 6)
        usage();
    get_source_ip(argv, params);
    get_victim_ip(argv, params);
    get_iface_info(argv, params);
    if (argc == 6)
    {
        params->victim_mac_str = str_malloc(24);
        memcpy(params->victim_mac_str, argv[5], strlen(argv[5]));
    }
}

int     main(int argc, char **argv)
{
    t_params params;

    myarpspoof(argc, argv, &params);
    return (SUCCESS);
}