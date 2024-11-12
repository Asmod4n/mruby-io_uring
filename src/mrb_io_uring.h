#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <sys/resource.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <liburing.h>
#include <mruby.h>
#include <mruby/data.h>
#include <mruby/variable.h>
#include <mruby/hash.h>
#include <mruby/error.h>
#include <mruby/class.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/io_uring.h>
#include <mruby/proc.h>
#include <sys/time.h>
#include <stdlib.h>
#include <mruby/ext/io.h>
#include <sys/poll.h>
#include <mruby/throw.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define NELEMS(argv) (sizeof(argv) / sizeof(argv[0]))

enum mrb_io_uring_op_types {
  SOCKET,
  ACCEPT,
  MULTISHOTACCEPT,
  RECV,
  SPLICE,
  SEND,
  SHUTDOWN,
  CLOSE,
  POLLADD,
  POLLMULTISHOT,
  POLLUPDATE,
  OPENAT2,
  READ,
  READFIXED,
  WRITE,
  CANCEL
};

static void
mrb_io_uring_queue_exit_gc(mrb_state *mrb, void *p)
{
  io_uring_queue_exit(p);
  mrb_free(mrb, p);
}
static const struct mrb_data_type mrb_io_uring_queue_type = {
  "$i_mrb_io_uring_queue_type", mrb_io_uring_queue_exit_gc
};

static const struct mrb_data_type mrb_io_uring_operation_type = {
  "$i_mrb_io_uring_operation_type", mrb_free
};

static const struct mrb_data_type mrb_io_uring_open_how_type = {
  "$i_mrb_io_uring_open_how_type", mrb_free
};

#define MRB_IORING_BUFFER_SIZE 131072

typedef struct {
  struct io_uring *ring;
  struct iovec *iovecs;
  unsigned long long *tags;
  mrb_value free_list;
  mrb_int allocated_buffers;
  mrb_int max_buffers;
} mrb_io_uring_buffers_t;

static void
mrb_io_uring_buffers_gc_free(mrb_state *mrb, void *p)
{
  mrb_io_uring_buffers_t *buffers_t = (mrb_io_uring_buffers_t *) p;
  mrb_free(mrb, buffers_t->iovecs);
  mrb_free(mrb, buffers_t->tags);
  mrb_free(mrb, p);
}

static const struct mrb_data_type mrb_io_uring_buffers_type = {
  "$i_mrb_io_uring__buffers_type", mrb_io_uring_buffers_gc_free
};