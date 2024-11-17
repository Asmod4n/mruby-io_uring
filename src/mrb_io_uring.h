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
#include <mruby/io_uring.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <sys/poll.h>
#include <mruby/throw.h>
#include <mruby/ext/io.h>
#include <stdlib.h>
#include <sys/param.h>

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
  CANCEL,
  LAST_TYPE = CANCEL
};

typedef struct {
  struct io_uring ring;
  struct io_uring_params params;
  mrb_value sqes;
  size_t allocated_buffers;
  size_t max_buffers;
  size_t total_used_buffer_memory;
  size_t memlock_limit;
  struct iovec *iovecs;
  unsigned long long *tags;
  mrb_int *calculated_sizes;
  mrb_value buffers;
  mrb_value free_list;
} mrb_io_uring_t;

typedef struct {
  mrb_int index;
  mrb_value buffer;
} mrb_io_uring_buffer_t;

static void
mrb_io_uring_queue_exit_gc(mrb_state *mrb, void *p)
{
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) p;
  io_uring_queue_exit(&mrb_io_uring->ring);
  mrb_free(mrb, mrb_io_uring->iovecs);
  mrb_free(mrb, mrb_io_uring->tags);
  mrb_free(mrb, mrb_io_uring->calculated_sizes);
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

#define MRB_IORING_DEFAULT_FIXED_BUFFER_SIZE 131072
#define MAX_BUFFER_SIZE (1 << 30) // Taken from the io_uring man pages: registered buffers musn't be larger than 1 GB.

static long page_size;
static size_t *precomputed_bins = NULL;
static size_t gem_load_count = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static mrb_bool can_use_buffers = FALSE;