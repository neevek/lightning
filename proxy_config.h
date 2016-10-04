#ifndef PROXY_CONFIG_H_
#define PROXY_CONFIG_H_

// returns 0 on success
int set_global_proxy(const char *host, int port);
int set_proxy_with_pac_file_url(const char *pac_file_url);
int disable_proxy();

#endif /* end of include guard: PROXY_CONFIG_H_ */

