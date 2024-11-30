#pragma once
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <liburing.h>
#include <mruby.h>
#include <mruby/data.h>
#include <pthread.h>
#include <sys/resource.h>
#include <mruby/error.h>
#include <string.h>
#include <mruby/hash.h>
#include <mruby/variable.h>
#include <mruby/array.h>
#include <mruby/ext/io_uring.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <sys/poll.h>
#include <mruby/throw.h>
#include <mruby/ext/io.h>
#include <sys/param.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define NELEMS(argv) (sizeof(argv) / sizeof(argv[0]))

typedef struct {
  struct io_uring ring;
  struct io_uring_params params;
  mrb_value sqes;
  struct RClass *operation_class;
  mrb_value at_ring_val;
  mrb_value at_type_val;
  mrb_sym at_sock_sym;
  mrb_value at_sock_val;
  mrb_sym at_buf_sym;
  mrb_value at_buf_val;
  mrb_value at_poll_mask_val;
  mrb_sym at_file_sym;
  mrb_value at_file_val;
  mrb_sym at_path_sym;
  mrb_value at_path_val;
  mrb_value at_directory_val;
  mrb_value at_open_how_val;
  mrb_value at_operation_val;
  mrb_sym at_res_sym;
  mrb_sym at_flags_sym;
  mrb_sym at_errno_sym;
  mrb_sym at_userdata_sym;
  mrb_value at_userdata_val;
  mrb_sym buf_index_sym;
  mrb_value buf_index_val;
  mrb_value socket_val;
  mrb_value accept_val;
  mrb_value multishot_accept_val;
  mrb_value connect_val;
  mrb_value at_addrinfo_val;
  mrb_value recv_val;
  mrb_value splice_val;
  mrb_value send_val;
  mrb_sym buf_was_frozen_sym;
  mrb_value buf_was_frozen_val;
  mrb_sym path_was_frozen_sym;
  mrb_value path_was_frozen_val;
  mrb_value shutdown_val;
  mrb_value close_val;
  mrb_value poll_add_val;
  mrb_value poll_multishot_val;
  mrb_value poll_update_val;
  mrb_value openat2_val;
  mrb_value read_val;
  mrb_value read_fixed_val;
  mrb_value write_val;
  mrb_value cancel_val;
  mrb_sym statx_sym;
  mrb_value statx_val;
  mrb_sym at_statx_sym;
  mrb_value at_statx_val;
  mrb_int fixed_buffer_size;
  mrb_value buffers;
  mrb_value free_list;
} mrb_io_uring_t;

static void
mrb_io_uring_queue_exit_gc(mrb_state *mrb, void *p)
{
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) p;
  io_uring_queue_exit(&mrb_io_uring->ring);
  mrb_free(mrb, p);
}
static const struct mrb_data_type mrb_io_uring_queue_type = {
  "$i_mrb_io_uring_queue_type", mrb_io_uring_queue_exit_gc
};

typedef struct {
  mrb_int index;
  mrb_value buffer;
} mrb_io_uring_buffer_t;

enum mrb_io_uring_op {
  MRB_IORING_OP_READ_FIXED,
  MRB_IORING_OP_ACCEPT,
  MRB_IORING_OP_SOCKET,
  MRB_IORING_OP_READ,
  MRB_IORING_OP_RECV,
  MRB_IORING_OP_WRITE,
  MRB_IORING_OP_SEND,
  MRB_IORING_OP_OPENAT2,
  MRB_IORING_OP_STATX,
  MRB_IORING_OP_CONNECT,
  MRB_IORING_OP_SPLICE,
  MRB_IORING_OP_SHUTDOWN,
  MRB_IORING_OP_CLOSE,
  MRB_IORING_OP_POLL_ADD,
  MRB_IORING_OP_POLL_MULTISHOT,
  MRB_IORING_OP_POLL_UPDATE,
  MRB_IORING_OP_CANCEL
};

static int can_use_high_bits = 0;
typedef struct {
    void *ptr;
    enum mrb_io_uring_op op;
} PtrAndInt;

static void
mrb_io_uring_operation_gc_free(mrb_state *mrb, void *p)
{
  if (!can_use_high_bits) mrb_free(mrb, p);
}
static const struct mrb_data_type mrb_io_uring_operation_type = {
  "$i_mrb_io_uring_operation_type", mrb_io_uring_operation_gc_free
};

static const struct mrb_data_type mrb_io_uring_open_how_type = {
  "$i_mrb_io_uring_open_how_type", mrb_free
};

static const struct mrb_data_type mrb_io_uring_statx_type = {
  "$i_mrb_io_uring_statx_type", mrb_free
};

static long page_size = 0;
static mrb_bool init_once_done = FALSE;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static mrb_bool can_use_buffers = FALSE;
#define MRB_IORING_DEFAULT_FIXED_BUFFER_SIZE 131072
