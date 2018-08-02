#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "globals.h"
#include "log.h"

struct config nwpd_config = {
        .log_level = LOG_LEVEL_INFO,
        .try_announce_period = 2,
        .monitor_ping_period = 5,
        .monitor_ack_timeout = 5,
        .monitor_investigative_ack_timeout = 5,
        .monitor_investigative_neigh_count = 10,
};

static char const *const usage_message =
        "usage: dhcpcd \t -i interface [-hlapkvn]\n"
        "\t\t[-h, --help]\n"
        "\t\t[-i, --interface iface]\n"
        "\t\t[-l, --log-level level]\n"
        "\t\t[-a, --try-announce seconds]\n"
        "\t\t[-p, --ping-period seconds]\n"
        "\t\t[-k, --ack-timeout seconds]\n"
        "\t\t[-v, --ivst-ack-timeout seconds]\n"
        "\t\t[-n, --ivst-neigh number]\n";

static void print_help()
{
        fprintf(stderr, usage_message);
}

static bool check_num(char *str)
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
                                {"help",             no_argument,       NULL,             'h'},
                                {"log-level",        required_argument, NULL,             'l'},
                                {"try-announce",     required_argument, NULL,             'a'},
                                {"ping-period",      required_argument, NULL,             'p'},
                                {"ack-timeout",      required_argument, NULL,             'k'},
                                {"ivst-ack-timeout", required_argument, NULL,             'v'},
                                {"ivst-neigh",       required_argument, NULL,             'n'},
                                {"interface",        required_argument, NULL,             'i'},
                                {NULL,0,NULL,0}
                        };
                int index;

                c = getopt_long(argc, argv, "hl:a:p:k:v:n:i:", long_options, &index);
                if (c == -1)
                        break;
                switch ((char)c) {
                case 'h':
                        print_help();
                        exit(0);
                case 'i':
                        nwpd_config.interface = strdup(optarg);
                        break;
                case 'l':
                        if (strcmp(optarg, "debug") == 0)
                                nwpd_config.log_level = LOG_LEVEL_DEBUG;
                        else if (strcmp(optarg, "info") == 0)
                                nwpd_config.log_level = LOG_LEVEL_INFO;
                        else if (strcmp(optarg, "warning") == 0)
                                nwpd_config.log_level = LOG_LEVEL_WARNING;
                        else if (strcmp(optarg, "error") == 0)
                                nwpd_config.log_level = LOG_LEVEL_ERROR;
                        else if (strcmp(optarg, "fatal") == 0)
                                nwpd_config.log_level = LOG_LEVEL_FATAL;
                        else {
                                fprintf(stderr, "nwpd: invalid log level value\n");
                                print_help();
                                exit(1);
                        }
                        break;
                case 'a':
                        if (check_num(optarg)) {
                                fprintf(stderr, "nwpd: invalid announce period value\n");
                                print_help();
                                exit(1);
                        }
                        nwpd_config.try_announce_period = atoi(optarg);
                        break;
                case 'p':
                        if (check_num(optarg)) {
                                fprintf(stderr, "nwpd: invalid ping period value\n");
                                print_help();
                                exit(1);
                        }
                        nwpd_config.monitor_ping_period = atoi(optarg);
                        break;
                case 'k':
                        if (check_num(optarg)) {
                                fprintf(stderr, "nwpd: invalid ack timeout value\n");
                                print_help();
                                exit(1);
                        }
                        nwpd_config.monitor_ack_timeout = atoi(optarg);
                        break;
                case 'v':
                        if (check_num(optarg)) {
                                fprintf(stderr, "nwpd: invalid investigative ack timeout value\n");
                                print_help();
                                exit(1);
                        }
                        nwpd_config.monitor_investigative_ack_timeout = atoi(optarg);
                        break;
                case 'n':
                        if (check_num(optarg)) {
                                fprintf(stderr, "nwpd: invalid investigative neighbor count value\n");
                                print_help();
                                exit(1);
                        }
                        nwpd_config.monitor_investigative_neigh_count = atoi(optarg);
                        break;
                default:
                        fprintf(stderr, "nwpd:missing/invalid options\n");
                        print_help();
                        exit(1);
                        break;
                }
        }

        if (nwpd_config.interface == NULL) {
                fprintf(stderr, "nwpd: interface not mentioned\n");
        }
}
