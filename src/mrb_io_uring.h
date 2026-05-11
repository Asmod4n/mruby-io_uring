#pragma once
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <liburing.h>
#include <pthread.h>
#include <sys/resource.h>
#include <string.h>
#include <sys/poll.h>
#include <mruby/io.h>
#include <sys/param.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <netinet/in.h>

#include <mruby.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/variable.h>
#include <mruby/array.h>
#include <mruby/ext/io_uring.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <mruby/presym.h>
#include <mruby/error.h>

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
  size_t fixed_buffer_size;
  mrb_value buffers;
  mrb_value free_pool;
  struct RClass *op_class;
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
} mrb_io_uring_fixed_buffer_t;

enum mrb_io_uring_op {
  MRB_IORING_OP_READ_FIXED,
  MRB_IORING_OP_SOCKET,
  MRB_IORING_OP_ACCEPT,
  MRB_IORING_OP_READ,
  MRB_IORING_OP_RECV,
  MRB_IORING_OP_WRITE,
  MRB_IORING_OP_SEND,
  MRB_IORING_OP_UNLINKAT,
  MRB_IORING_OP_OPENAT2,
  MRB_IORING_OP_STATX,
  MRB_IORING_OP_CONNECT,
  MRB_IORING_OP_SPLICE,
  MRB_IORING_OP_SHUTDOWN,
  MRB_IORING_OP_CLOSE,
  MRB_IORING_OP_POLL_ADD,
  MRB_IORING_OP_POLL_MULTISHOT,
  MRB_IORING_OP_POLL_UPDATE,
  MRB_IORING_OP_CANCEL,
  MRB_IORING_OP_BIND,
  MRB_IORING_OP_LISTEN,
  MRB_IORING_OP_WRITE_FIXED
};

/*
 * Per-operation header passed to io_uring as user_data.
 *
 * `op` is at offset 0 by design. The CQE handler dispatches on this
 * field and then immediately reads `op_obj` to recover the mruby
 * Operation, so a single load from the head of the cache line gets us
 * everything we need — no bit manipulation, no address-space
 * assumption, works on every CPU Linux supports.
 */
typedef struct {
    enum mrb_io_uring_op op;
    void *op_obj;  /* RBasic* of the Operation mruby object */
} mrb_io_uring_op_data_t;

static struct mrb_data_type mrb_io_uring_operation_type = {
  "$i_mrb_io_uring_operation_type", mrb_free
};

/*
 * Allocate an Operation in one shot. Equivalent to Data_Make_Struct,
 * but the macro's `static const strct zero = { 0 }; *(sval) = zero;`
 * doesn't compile in C++ for this struct (first field is an enum, no
 * implicit int->enum conversion) — and that copy would be wasted
 * anyway since we overwrite both fields immediately.
 *
 * Allocate the RData first with NULL payload so it's already
 * arena-rooted before the payload alloc happens; if mrb_malloc
 * raises, dfree(mrb_free) on NULL is a no-op. Then inline what the
 * old Ruby-side `initialize` did — iterate (sym, value) pairs into
 * the ivar table. C callers are trusted, so the per-pair type checks
 * are gone.
 */
static inline mrb_value
mrb_io_uring_op_alloc(mrb_state *mrb, struct RClass *op_class,
                      enum mrb_io_uring_op op,
                      const mrb_value *argv, mrb_int argc)
{
    struct RData *rdata = mrb_data_object_alloc(mrb, op_class, NULL,
                                                &mrb_io_uring_operation_type);
    mrb_io_uring_op_data_t *data =
        (mrb_io_uring_op_data_t *) mrb_malloc(mrb, sizeof(*data));
    data->op     = op;
    data->op_obj = rdata;
    rdata->data  = data;

    mrb_value op_val = mrb_obj_value(rdata);
    for (mrb_int i = 0; i + 1 < argc; i += 2) {
      mrb_iv_set(mrb, op_val, mrb_symbol(argv[i]), argv[i + 1]);
    }
    return op_val;
}

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
#define MRB_IORING_DEFAULT_FIXED_BUFFER_SIZE 65536

#ifndef MRB_UNSET_FROZEN_FLAG
#define MRB_UNSET_FROZEN_FLAG(o) ((o)->frozen = 0)
#endif