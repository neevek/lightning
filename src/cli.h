#ifndef CLI_H_
#define CLI_H_

int handle_remote_server_args(
    int argc, 
    const char **argv, 
    char **local_host,
    int *local_port,
    char **cipher_name,
    char **cipher_secret,
    char **user,
    char **log_file,
    int *daemon_flag
    );

int handle_local_server_args(
    int argc, 
    const char **argv, 
    char **local_host,
    int *local_port,
    char **remote_host,
    int *remote_port,
    char **cipher_name,
    char **cipher_secret,
    char **user,
    char **log_file,
    int *daemon_flag
    );

#endif /* end of include guard: CLI_H_ */
