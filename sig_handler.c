#include "sig_handler.h"
#include "log/log.h"
#ifdef __APPLE__
#include "proxy_config.h"
#endif

#include <stdlib.h>
#include <signal.h>
#include <errno.h>

static void register_sig_handler(int sig) {
  if (signal(sig, handle_sig) == SIG_ERR) {
    LOG_W("Cannot handle signal: %d, %s", sig, strerror(errno));
  }
}

void register_sig_handlers() {
#ifdef __APPLE__
  register_sig_handler(SIGINT);
  register_sig_handler(SIGHUP);
  register_sig_handler(SIGTERM);
#endif
}

void handle_sig(int sig) {
#ifdef __APPLE__
  LOG_I("received signal: %d", sig);
  disable_proxy();
  exit(0);
#endif
}
