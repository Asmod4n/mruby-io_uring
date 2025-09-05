#pragma once
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <liburing.h>
#include <pthread.h>
#include <sys/resource.h>
#include <string.h>
#include <sys/poll.h>
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
  struct RClass *operation_class;
  size_t fixed_buffer_size;
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

static inline void* decode_operation_inline(uintptr_t packed_value) {
    size_t ptr_bits = sizeof(void*) * 8;
    size_t op_bits  = 8;
    uintptr_t ptr_mask = ((uintptr_t)1 << (ptr_bits - op_bits)) - 1;
    return (void*)(packed_value & ptr_mask);
}

static inline enum mrb_io_uring_op decode_op_inline(uintptr_t packed_value) {
    size_t ptr_bits = sizeof(void*) * 8;
    size_t op_bits  = 8;
    return (enum mrb_io_uring_op)(packed_value >> (ptr_bits - op_bits));
}

static inline uintptr_t encode_operation_op_inline(mrb_state *mrb,
                                                   void *ptr,
                                                   enum mrb_io_uring_op op) {
    size_t ptr_bits = sizeof(void*) * 8;
    size_t op_bits  = 8;
    uintptr_t ptr_mask = ((uintptr_t)1 << (ptr_bits - op_bits)) - 1;
    return ((uintptr_t)ptr & ptr_mask) | ((uintptr_t)op << (ptr_bits - op_bits));
}

typedef struct {
    void *ptr;
    enum mrb_io_uring_op op;
} PointerWithOp;

static inline void* decode_operation_heap(uintptr_t packed_value) {
    return ((PointerWithOp *)packed_value)->ptr;
}

static inline enum mrb_io_uring_op decode_op_heap(uintptr_t packed_value) {
    return ((PointerWithOp *)packed_value)->op;
}

static inline uintptr_t encode_operation_op_heap( mrb_state *mrb,
                                                  void *ptr,
                                                  enum mrb_io_uring_op op) {
    PointerWithOp *pwo = (PointerWithOp *) mrb_malloc(mrb, sizeof(PointerWithOp));
    pwo->ptr = ptr;
    pwo->op  = op;
    return (uintptr_t)pwo;
}

uintptr_t (*encode_operation_op)(mrb_state*, void*, enum mrb_io_uring_op);
void* (*decode_operation)(uintptr_t);
enum mrb_io_uring_op (*decode_op)(uintptr_t);

static struct mrb_data_type mrb_io_uring_operation_type = {
  "$i_mrb_io_uring_operation_type", mrb_free
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
#define MRB_IORING_DEFAULT_FIXED_BUFFER_SIZE 65536

#ifndef MRB_UNSET_FROZEN_FLAG
#define MRB_UNSET_FROZEN_FLAG(o) ((o)->frozen = 0)
#endif