#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "globals.h"
#include "log.h"

struct config nwpd_config = {
        .try_announce_period = 2,
        .monitor_ping_period = 5,
        .monitor_ack_timeout = 5,
        .monitor_investigative_ack_timeout = 5,
        .monitor_investigative_neigh_count = 10,
};

bool check_num(char *str)
{
        int i;
        for (i = 0; i < strlen(str); i++)
                if (!(str[i] >= '0' && str[i] <= '9'))
                        return false;
        return true;
}

void init_config(int argc, char **argv)
{
        int c;

        while (1) {
                static struct option long_options[] =
                        {
                                {"log-level",        optional_argument, NULL, 'l'},
                                {"try-announce",     optional_argument, NULL, 'a'},
                                {"ping-period",      optional_argument, NULL, 'p'},
                                {"ack-timeout",      optional_argument, NULL, 'k'},
                                {"ivst-ack-timeout", optional_argument, NULL, 'v'},
                                {"ivst-neigh",       optional_argument, NULL, 'n'},

                                {"interface",        required_argument, NULL, 'i'},
                                {0,0,NULL,0}
                        };
                int index;

                c = getopt_long(argc, argv, "lapkvni:", long_options, &index);
                if (c == -1)
                        break;
                switch (c) {
                case 'i':
                        nwpd_config.interface = strdup(optarg);
                        break;
                case 'l':
                        if (strcmp(optarg, "debug"))
                                nwpd_config.log_level = LOG_LEVEL_DEBUG;
                        else if (strcmp(optarg, "info"))
                                nwpd_config.log_level = LOG_LEVEL_INFO;
                        else if (strcmp(optarg, "warning"))
                                nwpd_config.log_level = LOG_LEVEL_WARNING;
                        else if (strcmp(optarg, "error"))
                                nwpd_config.log_level = LOG_LEVEL_ERROR;
                        else if (strcmp(optarg, "fatal"))
                                nwpd_config.log_level = LOG_LEVEL_FATAL;
                        else {
                                fprintf(stderr, "invalid log level value\n");
                                exit(1);
                        }
                        break;
                case 'a':
                        if (check_num(optarg)) {
                                fprintf(stderr, "invalid announce period value\n");
                                exit(1);
                        }
                        nwpd_config.try_announce_period = atoi(optarg);
                        break;
                case 'p':
                        if (check_num(optarg)) {
                                fprintf(stderr, "invalid ping period value\n");
                                exit(1);
                        }
                        nwpd_config.monitor_ping_period = atoi(optarg);
                        break;
                case 'k':
                        if (check_num(optarg)) {
                                fprintf(stderr, "invalid ack timeout value\n");
                                exit(1);
                        }
                        nwpd_config.monitor_ack_timeout = atoi(optarg);
                        break;
                case 'v':
                        if (check_num(optarg)) {
                                fprintf(stderr, "invalid investigative ack timeout value\n");
                                exit(1);
                        }
                        nwpd_config.monitor_investigative_ack_timeout = atoi(optarg);
                        break;
                case 'n':
                        if (check_num(optarg)) {
                                fprintf(stderr, "invalid investigative neighbor count value\n");
                                exit(1);
                        }
                        nwpd_config.monitor_investigative_neigh_count = atoi(optarg);
                        break;
                default:
                        fprintf(stderr, "missing/invalid options\n");
                        exit(1);
                        break;
                }
        }
}
