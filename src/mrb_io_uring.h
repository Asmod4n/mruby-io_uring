#include <mruby.h>
#include <string.h>
#include <mruby/data.h>
#include <mruby/variable.h>
#include <mruby/hash.h>
#include <mruby/error.h>
#include <mruby/class.h>
#include <liburing.h>
#include <netinet/in.h>
#include <netdb.h>
#include <mruby/string.h>
#include <mruby/ext/io.h>
#include <mruby/array.h>
#include <mruby/io_uring.h>
#include <unistd.h>
#include <err.h>
#include <stdlib.h>

# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)

enum userdata_types {
  TCPSERVER,
  ACCEPT,
  RECV,
  SEND,
  CLOSE
};

typedef struct {
  enum userdata_types type;
  mrb_value type_sym;
  int socket;
  int port;
  struct sockaddr_storage sa;
  socklen_t salen;
} mrb_io_uring_userdata_t;

static void
mrb_io_uring_queue_exit_gc(mrb_state *mrb, void *p)
{
  io_uring_queue_exit(p);
  mrb_free(mrb, p);
}

static const struct mrb_data_type mrb_io_uring_queue_type = {
  "$i_mrb_io_uring_queue_type", mrb_io_uring_queue_exit_gc
};

static const struct mrb_data_type mrb_io_uring_userdata_type = {
  "$i_mrb_io_uring_userdata_type", mrb_free
};

static const struct mrb_data_type mrb_io_uring_socket_type = {
  "$i_mrb_io_uring_socket_type", NULL
};

