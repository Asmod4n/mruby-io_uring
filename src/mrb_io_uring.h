#define _GNU_SOURCE
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
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

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define NELEMS(argv) (sizeof(argv) / sizeof(argv[0]))

enum mrb_io_uring_userdata_types {
  SOCKET,
  ACCEPT,
  RECV,
  SPLICE,
  SEND,
  SHUTDOWN,
  CLOSE,
  POLLADD
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

static const struct mrb_data_type mrb_io_uring_userdata_type = {
  "$i_mrb_io_uring_userdata_type", mrb_free
};

static const struct mrb_data_type mrb_io_uring_sqe_type = {
  "$i_mrb_io_uring_sqe_type", NULL
};

static const struct mrb_data_type mrb_io_uring_cqe_type = {
  "$i_mrb_io_uring_cqe_type", mrb_free
};
