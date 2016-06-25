#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

void local_server_usage(const char *cmd, int exit_code) {
  fprintf(stderr, 
      "Usage: %s <options>\n"
      "    -h, --local_host    the host this server is running on\n"
      "    -p, --local_port    the port this server to be bound\n"
      "    -H, --remote_host   the host this server connects to\n"
      "    -P, --remote_host   the port this server connects to\n"
      "    -c, --cipher_name   the cipher used to encrypt & decrypt the payloads\n"
      "    -s, --cipher_secret the secret key\n"
      "    -u, --user          run as user\n"
      "    -D, --daemon        run the process in the background\n"
      "    --help          print this help message\n"
      , cmd);
  exit(exit_code);
}

void remote_server_usage(const char *cmd, int exit_code) {
  fprintf(stderr, 
      "Usage: %s <options>\n"
      "    -h, --local_host    the host this server is running on\n"
      "    -p, --local_port    the port this server to be bound\n"
      "    -c, --cipher_name   the cipher used to encrypt & decrypt the payloads\n"
      "    -s, --cipher_secret the secret key\n"
      "    -u, --user          run as user\n"
      "    -D, --daemon        run the process in the background\n"
      "    --help          print this help message\n"
      , cmd);
  exit(exit_code);
}

void check_option_value(void *value, const char *msg, int for_local_server, 
    const char *cmd) {
  if (value == NULL) {
    fprintf(stderr, "%s\n", msg);
    if (for_local_server) {
      local_server_usage(cmd, 0);
    } else {
      remote_server_usage(cmd, 0);
    }
  }
}

void handle_remote_server_args(
    int argc, 
    const char **argv, 
    char **local_host,
    int *local_port,
    char **cipher_name,
    char **cipher_secret,
    char **user,
    int *daemon_flag
    ) {

  *local_host = NULL;
  *local_port = 0;
  *cipher_name = NULL;
  *cipher_secret = NULL;
  *user = NULL;
  *daemon_flag = 0;

  static struct option long_options[] = {
    {"help",          no_argument,       0, 1},
    {"local_host",    required_argument, 0, 'h'},
    {"local_port",    required_argument, 0, 'p'},
    {"cipher_name",   required_argument, 0, 'c'},
    {"cipher_secret", required_argument, 0, 's'},
    {"user",          required_argument, 0, 'u'},
    {"daemon",        no_argument,       0, 'D'},
    {0, 0, 0, 0}
  };

  int optind = 0;
  char c;
  while((c = getopt_long(argc, (char **)argv, "h:p:c:s:u:D",
          long_options, &optind)) != -1) {
    switch(c) {
      case 0:
        if (strcmp(long_options[optind].name, "help") == 0) {
          remote_server_usage(argv[0], 0);
        } else if (strcmp(long_options[optind].name, "daemon") == 0) {
          *daemon_flag = 1;
        }
        break;
      case 'h':
        *local_host = optarg;
        break;
      case 'p':
        *local_port = atoi(optarg);
        check_option_value((void *)(intptr_t)*local_port, 
            "invalid value for <-p, --local_port>", 0, argv[0]);
        break;
      case 'c':
        *cipher_name = optarg;
        break;
      case 's':
        *cipher_secret = optarg;
        break;
      case 'u':
        *user = optarg;
        break;
      case 'D':
        *daemon_flag = 1;
        break;
      default:
        remote_server_usage(argv[0], 1);
    }
  }
  check_option_value(*local_host, "<-h, --local_host> is required", 0, argv[0]);
  check_option_value(*cipher_name, "<-c, --cipher_name> is required", 0, argv[0]);
  check_option_value(*cipher_secret, "<-s, --cipher_secret> is required", 0, argv[0]);
  check_option_value((void *)(intptr_t)*local_port, "<-p, --local_port> is required", 0, argv[0]);
}

void handle_local_server_args(
    int argc, 
    const char **argv, 
    char **local_host,
    int *local_port,
    char **remote_host,
    int *remote_port,
    char **cipher_name,
    char **cipher_secret,
    char **user,
    int *daemon_flag
    ) {

  *local_host = NULL;
  *local_port = 0;
  *remote_host = NULL;
  *remote_port = 0;
  *cipher_name = NULL;
  *cipher_secret = NULL;
  *user = NULL;

  static struct option long_options[] = {
    {"help",          no_argument,       0, 1},
    {"local_host",    required_argument, 0, 'h'},
    {"local_port",    required_argument, 0, 'p'},
    {"remote_host",   required_argument, 0, 'H'},
    {"remote_port",   required_argument, 0, 'P'},
    {"cipher_name",   required_argument, 0, 'c'},
    {"cipher_secret", required_argument, 0, 's'},
    {"user",          required_argument, 0, 'u'},
    {"daemon",        no_argument,       0, 'D'},
    {0, 0, 0, 0}
  };

  int optind = 0;
  char c;
  while((c = getopt_long(argc, (char **)argv, "h:p:H:P:c:s:u:D",
          long_options, &optind)) != -1) {
    switch(c) {
      case 0:
        if (strcmp(long_options[optind].name, "help") == 0) {
          local_server_usage(argv[0], 0);
        }
        break;
      case 'h':
        *local_host = optarg;
        break;
      case 'p':
        *local_port = atoi(optarg);
        check_option_value((void *)(intptr_t)*local_port, 
            "invalid value for <-p, --local_port>", 1, argv[0]);
        break;
      case 'H':
        *remote_host = optarg;
        break;
      case 'P':
        *remote_port = atoi(optarg);
        check_option_value((void *)(intptr_t)*remote_port, 
            "invalid value for <-P, --remote_port>", 1, argv[0]);
        break;
      case 'c':
        *cipher_name = optarg;
        break;
      case 's':
        *cipher_secret = optarg;
        break;
      case 'u':
        *user = optarg;
        break;
      case 'D':
        *daemon_flag = 1;
        break;
      default:
        local_server_usage(argv[0], 1);
    }
  }
  check_option_value(*local_host, "<-h, --local_host> is required", 1, argv[0]);
  check_option_value(*remote_host, "<-H, --remote_host> is required", 1, argv[0]);
  check_option_value(*cipher_name, "<-c, --cipher_name> is required", 1, argv[0]);
  check_option_value(*cipher_secret, "<-s, --cipher_secret> is required", 1, argv[0]);
  check_option_value((void *)(intptr_t)*local_port, "<-p, --local_port> is required", 1, argv[0]);
  check_option_value((void *)(intptr_t)*remote_port, "<-P, --remote_port> is required", 1, argv[0]);
}
