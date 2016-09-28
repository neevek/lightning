#ifndef CLI_H_
#define CLI_H_
#include "defs.h"

void handle_remote_server_args(
    int argc, const char **argv, RemoteServerCliCfg *cfg);

void handle_local_server_args(
    int argc, const char **argv, LocalServerCliCfg *cfg);

#endif /* end of include guard: CLI_H_ */
