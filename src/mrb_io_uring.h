#include "liburing/io_uring.h"
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

typedef struct {
  struct io_uring ring;
  struct io_uring_params params;
  mrb_value sqes;
  mrb_value buffers;
  mrb_value buffer_lookup;
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
  mrb_free(mrb, p);
}
static const struct mrb_data_type mrb_io_uring_queue_type = {
  "$i_mrb_io_uring_queue_type", mrb_io_uring_queue_exit_gc
};

static int use_high_bits_temp = 0;
const int const *USE_HIGH_BITS;

static void
mrb_io_uring_operation_gc_free(mrb_state *mrb, void *p)
{
  if (!*USE_HIGH_BITS) mrb_free(mrb, p);
}

static const struct mrb_data_type mrb_io_uring_operation_type = {
  "$i_mrb_io_uring_operation_type", mrb_io_uring_operation_gc_free
};


typedef struct {
    void *ptr;
    uint8_t op;
} PtrAndInt;


static void
initialize_high_bits_check(mrb_state *mrb)
{
    void *ptr = mrb_malloc(mrb, 1);

    uintptr_t address = (uintptr_t)ptr;
    use_high_bits_temp = !(address & 0xFFFF000000000000ULL);

    mrb_free(mrb, ptr);
    USE_HIGH_BITS = &use_high_bits_temp;
}

static uint64_t
encode_operation_op(mrb_state *mrb, void *ptr, uint8_t op)
{
    if (*USE_HIGH_BITS) {
        return ((uintptr_t)ptr & 0x0000FFFFFFFFFFFFULL) | ((uint64_t)(op) << (64 - 8));
    } else {
        PtrAndInt *pai = mrb_malloc(mrb, sizeof(PtrAndInt));
        pai->ptr = ptr;
        pai->op = op;
        return (uintptr_t)pai;
    }
}

static void *
decode_operation(uint64_t packed_value)
{
    if (*USE_HIGH_BITS) {
        return (void *)(packed_value & 0x0000FFFFFFFFFFFFULL);
    } else {
        PtrAndInt *pai = (PtrAndInt *)packed_value;
        return pai->ptr;
    }
}

static uint8_t
decode_op(uint64_t packed_value)
{
    if (*USE_HIGH_BITS) {
        return (uint8_t)(packed_value >> (64 - 8));
    } else {
        PtrAndInt *pai = (PtrAndInt *)packed_value;
        return pai->op;
    }
}

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