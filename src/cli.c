#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

void local_server_usage(const char *cmd, int exit_code) {
  fprintf(stderr, 
      "Usage: %s <options>\n"
      "    --help          print this help message\n"
      "    --local_host    the host this server is running on\n"
      "    --local_port    the port this server to be bound\n"
      "    --remote_host   the host this server connects to\n"
      "    --remote_host   the port this server connects to\n"
      "    --cipher_name   the cipher used to encrypt & decrypt the payloads\n"
      "    --cipher_secret the secret key\n"
      , cmd);
  exit(exit_code);
}

void remote_server_usage(const char *cmd, int exit_code) {
  fprintf(stderr, 
      "Usage: %s <options>\n"
      "    --help          print this help message\n"
      "    --local_host    the host this server is running on\n"
      "    --local_port    the port this server to be bound\n"
      "    --cipher_name   the cipher used to encrypt & decrypt the payloads\n"
      "    --cipher_secret the secret key\n"
      , cmd);
  exit(exit_code);
}

void check_option_value(void *value, const char *msg) {
  if (value == NULL) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
  }
}

void check_port(int port, const char *msg) {
  if (port == 0) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
  }
}

void handle_remote_server_args(
    int argc, 
    const char **argv, 
    char **local_host,
    int *local_port,
    char **cipher_name,
    char **cipher_secret) {

  *local_host = NULL;
  *local_port = 0;
  *cipher_name = NULL;
  *cipher_secret = NULL;

  static struct option long_options[] = {
    {"help",          no_argument,       0, 1},
    {"local_host",    required_argument, 0, 'a'},
    {"local_port",    required_argument, 0, 'b'},
    {"cipher_name",   required_argument, 0, 'c'},
    {"cipher_secret",  required_argument, 0, 'd'},
    {0, 0, 0, 0}
  };

  int optind = 0;
  char c;
  while((c = getopt_long(argc, (char **)argv, "a:b:c:d:",
          long_options, &optind)) != -1) {
    switch(c) {
      case 0:
        if (strcmp(long_options[optind].name, "help") == 0) {
          remote_server_usage(argv[0], 0);
        }
        break;
      case 'a':
        *local_host = optarg;
        break;
      case 'b':
        *local_port = atoi(optarg);
        check_port(*local_port, "invalid --local_port");
        break;
      case 'c':
        *cipher_name = optarg;
        break;
      case 'd':
        *cipher_secret = optarg;
        break;
      default:
        remote_server_usage(argv[0], 1);
    }
  }
  check_option_value(*local_host, "--local_host is required");
  check_option_value(*cipher_name, "--cipher_name is required");
  check_option_value(*cipher_secret, "--cipher_secret is required");
  check_port(*local_port, "--local_port is required");
}

void handle_local_server_args(
    int argc, 
    const char **argv, 
    char **local_host,
    int *local_port,
    char **remote_host,
    int *remote_port,
    char **cipher_name,
    char **cipher_secret) {

  *local_host = NULL;
  *local_port = 0;
  *remote_host = NULL;
  *remote_port = 0;
  *cipher_name = NULL;
  *cipher_secret = NULL;

  static struct option long_options[] = {
    {"help",          no_argument,       0, 1},
    {"local_host",    required_argument, 0, 'a'},
    {"local_port",    required_argument, 0, 'b'},
    {"remote_host",   required_argument, 0, 'c'},
    {"remote_port",   required_argument, 0, 'd'},
    {"cipher_name",   required_argument, 0, 'e'},
    {"cipher_secret",  required_argument, 0, 'f'},
    {0, 0, 0, 0}
  };

  int optind = 0;
  char c;
  while((c = getopt_long(argc, (char **)argv, "a:b:c:d:e:f:",
          long_options, &optind)) != -1) {
    switch(c) {
      case 0:
        if (strcmp(long_options[optind].name, "help") == 0) {
          local_server_usage(argv[0], 0);
        }
        break;
      case 'a':
        *local_host = optarg;
        break;
      case 'b':
        *local_port = atoi(optarg);
        check_port(*local_port, "invalid --local_port");
        break;
      case 'c':
        *remote_host = optarg;
        break;
      case 'd':
        *remote_port = atoi(optarg);
        check_port(*remote_port, "invalid --remote_port");
        break;
      case 'e':
        *cipher_name = optarg;
        break;
      case 'f':
        *cipher_secret = optarg;
        break;
      default:
        local_server_usage(argv[0], 1);
    }
  }
  check_option_value(*local_host, "--local_host is required");
  check_option_value(*remote_host, "--remote_host is required");
  check_option_value(*cipher_name, "--cipher_name is required");
  check_option_value(*cipher_secret, "--cipher_secret is required");
  check_port(*local_port, "--local_port is required");
  check_port(*remote_port, "--remote_port is required");
}
