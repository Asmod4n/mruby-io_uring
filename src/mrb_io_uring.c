#include "mrb_io_uring.h"

static mrb_value
mrb_io_uring_queue_init_params(mrb_state *mrb, mrb_value self)
{
  mrb_int fixed_buffer_size = MRB_IORING_DEFAULT_FIXED_BUFFER_SIZE, entries = 2048, flags = 0;
  mrb_get_args(mrb, "|iii", &fixed_buffer_size, &entries, &flags);
  if (fixed_buffer_size < page_size) {
#ifdef MRB_DEBUG
      mrb_warn(mrb, "fixed_buffer_size '%i' too small, adjusting to page size: %i", fixed_buffer_size, page_size);
#endif
      fixed_buffer_size = page_size;
  } else if (fixed_buffer_size > (1 << 30)) {
#ifdef MRB_DEBUG
      mrb_warn(mrb, "fixed_buffer_size '%i' too large, adjusting to max value: %i", fixed_buffer_size, (1 << 30));
#endif
      fixed_buffer_size = (1 << 30);
  } else if (fixed_buffer_size % page_size != 0) {
      long adjusted_fixed_buffer_size = (fixed_buffer_size / page_size) * page_size;
#ifdef MRB_DEBUG
      mrb_warn(mrb, "fixed_buffer_size '%i' not a multiple of page size, adjusting to nearest multiple: %i", fixed_buffer_size, adjusted_fixed_buffer_size);
#endif
      fixed_buffer_size = adjusted_fixed_buffer_size;
  }
  if (unlikely(entries <= 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too few entries");
  }
  entries = MIN(entries, 32768);
  if (unlikely(flags < 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "flags musn't be negative");
  }
  flags |= IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_COOP_TASKRUN|IORING_SETUP_DEFER_TASKRUN;

  struct rlimit limit;
  if (unlikely(getrlimit(RLIMIT_MEMLOCK, &limit)) == -1) {
    mrb_sys_fail(mrb, "getrlimit");
  }
  limit.rlim_cur = limit.rlim_max;
  if (unlikely(setrlimit(RLIMIT_MEMLOCK, &limit)) == -1) {
    mrb_sys_fail(mrb, "setrlimit");
  }

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*mrb_io_uring));
  mrb_data_init(self, mrb_io_uring, &mrb_io_uring_queue_type);
  memset(mrb_io_uring, '\0', sizeof(*mrb_io_uring));
  mrb_io_uring->params.flags = flags;

  int ret = io_uring_queue_init_params((unsigned int) entries, &mrb_io_uring->ring, &mrb_io_uring->params);
  if (ret != 0) {
    memset(mrb_io_uring, '\0', sizeof(*mrb_io_uring));
    ret = io_uring_queue_init_params((unsigned int) entries, &mrb_io_uring->ring, &mrb_io_uring->params);
  }
  if (likely(ret == 0)) {
    mrb_io_uring->sqes = mrb_hash_new(mrb);
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sqes"), mrb_io_uring->sqes);
    mrb_io_uring->operation_class = mrb_class_get_under_id(mrb, mrb_class(mrb, self), mrb_intern_lit(mrb, "Operation"));
    mrb_io_uring->at_ring_val = mrb_symbol_value(mrb_intern_lit(mrb, "@ring"));
    mrb_io_uring->at_type_val = mrb_symbol_value(mrb_intern_lit(mrb, "@type"));
    mrb_io_uring->at_sock_sym = mrb_intern_lit(mrb, "@sock");
    mrb_io_uring->at_sock_val = mrb_symbol_value(mrb_io_uring->at_sock_sym);
    mrb_io_uring->at_buf_sym = mrb_intern_lit(mrb, "@buf");
    mrb_io_uring->at_buf_val = mrb_symbol_value(mrb_io_uring->at_buf_sym);
    mrb_io_uring->at_poll_mask_val = mrb_symbol_value(mrb_intern_lit(mrb, "@poll_mask"));
    mrb_io_uring->at_file_sym = mrb_intern_lit(mrb, "@file");
    mrb_io_uring->at_file_val = mrb_symbol_value(mrb_io_uring->at_file_sym);
    mrb_io_uring->at_path_sym = mrb_intern_lit(mrb, "@path");
    mrb_io_uring->at_path_val = mrb_symbol_value( mrb_io_uring->at_path_sym);
    mrb_io_uring->at_directory_val = mrb_symbol_value(mrb_intern_lit(mrb, "@directory"));
    mrb_io_uring->at_open_how_val = mrb_symbol_value(mrb_intern_lit(mrb, "@open_how"));
    mrb_io_uring->at_operation_val = mrb_symbol_value(mrb_intern_lit(mrb, "@operation"));
    mrb_io_uring->at_res_sym = mrb_intern_lit(mrb, "@res");
    mrb_io_uring->at_flags_sym = mrb_intern_lit(mrb, "@flags");
    mrb_io_uring->at_errno_sym = mrb_intern_lit(mrb, "@errno");
    mrb_io_uring->at_userdata_sym = mrb_intern_lit(mrb, "@userdata");
    mrb_io_uring->at_userdata_val = mrb_symbol_value(mrb_io_uring->at_userdata_sym);
    mrb_io_uring->buf_index_sym = mrb_intern_lit(mrb, "buf_index");
    mrb_io_uring->buf_index_val = mrb_symbol_value(mrb_io_uring->buf_index_sym);
    mrb_io_uring->socket_val = mrb_symbol_value(mrb_intern_lit(mrb, "socket"));
    mrb_io_uring->accept_val = mrb_symbol_value(mrb_intern_lit(mrb, "accept"));
    mrb_io_uring->multishot_accept_val = mrb_symbol_value(mrb_intern_lit(mrb, "multishot_accept"));
    mrb_io_uring->connect_val = mrb_symbol_value(mrb_intern_lit(mrb, "connect"));
    mrb_io_uring->at_addrinfo_val = mrb_symbol_value(mrb_intern_lit(mrb, "@addrinfo"));
    mrb_io_uring->recv_val = mrb_symbol_value(mrb_intern_lit(mrb, "recv"));
    mrb_io_uring->splice_val = mrb_symbol_value(mrb_intern_lit(mrb, "splice"));
    mrb_io_uring->send_val = mrb_symbol_value(mrb_intern_lit(mrb, "send"));
    mrb_io_uring->buf_was_frozen_sym = mrb_intern_lit(mrb, "buf_was_frozen");
    mrb_io_uring->buf_was_frozen_val = mrb_symbol_value(mrb_io_uring->buf_was_frozen_sym);
    mrb_io_uring->path_was_frozen_sym = mrb_intern_lit(mrb, "path_was_frozen");
    mrb_io_uring->path_was_frozen_val = mrb_symbol_value(mrb_io_uring->path_was_frozen_sym);
    mrb_io_uring->shutdown_val = mrb_symbol_value(mrb_intern_lit(mrb, "shutdown"));
    mrb_io_uring->close_val = mrb_symbol_value(mrb_intern_lit(mrb, "close"));
    mrb_io_uring->poll_add_val = mrb_symbol_value(mrb_intern_lit(mrb, "poll_add"));
    mrb_io_uring->poll_multishot_val = mrb_symbol_value(mrb_intern_lit(mrb, "poll_multishot"));
    mrb_io_uring->poll_update_val = mrb_symbol_value(mrb_intern_lit(mrb, "poll_update"));
    mrb_io_uring->openat2_val = mrb_symbol_value(mrb_intern_lit(mrb, "openat2"));
    mrb_io_uring->read_val = mrb_symbol_value(mrb_intern_lit(mrb, "read"));
    mrb_io_uring->read_fixed_val = mrb_symbol_value(mrb_intern_lit(mrb, "read_fixed"));
    mrb_io_uring->write_val = mrb_symbol_value(mrb_intern_lit(mrb, "write"));
    mrb_io_uring->cancel_val = mrb_symbol_value(mrb_intern_lit(mrb, "cancel"));
    mrb_io_uring->statx_sym = mrb_intern_lit(mrb, "statx");
    mrb_io_uring->statx_val = mrb_symbol_value(mrb_io_uring->statx_sym);
    mrb_io_uring->at_statx_sym = mrb_intern_lit(mrb, "@statx");
    mrb_io_uring->at_statx_val = mrb_symbol_value(mrb_io_uring->at_statx_sym);

    if (can_use_buffers) {
      size_t max_buffers = MIN(limit.rlim_max / fixed_buffer_size, 16384);
      ret = io_uring_register_buffers_sparse(&mrb_io_uring->ring, max_buffers);
      if (likely(ret == 0)) {
        mrb_io_uring->fixed_buffer_size = fixed_buffer_size;
        mrb_io_uring->buffers = mrb_ary_new(mrb);
        mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "buffers"), mrb_io_uring->buffers);
        mrb_io_uring->free_list = mrb_ary_new(mrb);
        mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "free_list"), mrb_io_uring->free_list);
      } else {
        errno = -ret;
        mrb_sys_fail(mrb, "io_uring_register_buffers_sparse");
      }
    }
  } else {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_queue_init");
  }

  return self;
}

static mrb_value
mrb_io_uring_get_fixed_buffer_size(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  return mrb_int_value(mrb, mrb_io_uring->fixed_buffer_size);
}

static mrb_io_uring_buffer_t
mrb_io_uring_buffer_get(mrb_state *mrb, mrb_io_uring_t *mrb_io_uring)
{
  if (RARRAY_LEN(mrb_io_uring->free_list) > 0) {
    mrb_value index_val = mrb_ary_pop(mrb, mrb_io_uring->free_list);
    mrb_int index = mrb_as_int(mrb, index_val);
    mrb_io_uring_buffer_t result = {index, mrb_ary_ref(mrb, mrb_io_uring->buffers, index) };

    return result;
  }

  mrb_int num_buffers = RARRAY_LEN(mrb_io_uring->buffers);
  mrb_value buffer = mrb_str_new_capa(mrb, mrb_io_uring->fixed_buffer_size - 1);
  mrb_obj_freeze(mrb, buffer);

  struct iovec iovec = { RSTRING_PTR(buffer), mrb_io_uring->fixed_buffer_size };
  int ret = io_uring_register_buffers_update_tag(&mrb_io_uring->ring, num_buffers, &iovec, NULL, 1);
  if (likely(ret == 1)) {
    mrb_io_uring_buffer_t result = { num_buffers,  buffer };
    mrb_ary_push(mrb, mrb_io_uring->buffers, buffer);

    return result;
  } else {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_register_buffers_update_tag");
  }
}

static void
mrb_io_uring_return_used_buffer(mrb_state *mrb, mrb_io_uring_t *mrb_io_uring, mrb_value operation)
{
  mrb_value index_val = mrb_iv_get(mrb, operation, mrb_io_uring->buf_index_sym);
  mrb_int index = mrb_as_int(mrb, index_val);
  if (unlikely(!mrb_string_p(mrb_ary_ref(mrb, mrb_io_uring->buffers, index)))) {
    mrb_raise(mrb, E_TYPE_ERROR, "buf not found");
  }

  mrb_ary_push(mrb, mrb_io_uring->free_list, index_val);
}

static mrb_value
mrb_io_uring_submit(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  int ret = io_uring_submit(&mrb_io_uring->ring);
  if (unlikely(ret < 0)) {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_submit");
  }

  return mrb_int_value(mrb, ret);
}

static struct io_uring_sqe *
mrb_io_uring_get_sqe(mrb_state *mrb, struct io_uring *ring)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (unlikely(!sqe)) {
    mrb_raise(mrb, E_IO_URING_SQ_RING_FULL_ERROR, "SQ ring is currently full and entries must be submitted for processing before new ones can get allocated");
  }
  return sqe;
}

static uint64_t
encode_operation_op(mrb_state *mrb, void *ptr, enum mrb_io_uring_op op)
{
  if (likely(can_use_high_bits)) {
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
  if (likely(can_use_high_bits)) {
    return (void *)(packed_value & 0x0000FFFFFFFFFFFFULL);
  } else {
    PtrAndInt *pai = (PtrAndInt *)packed_value;
    return pai->ptr;
  }
}

static enum mrb_io_uring_op
decode_op(uint64_t packed_value)
{
  if (likely(can_use_high_bits)) {
    return (enum mrb_io_uring_op)(packed_value >> (64 - 8));
  } else {
    PtrAndInt *pai = (PtrAndInt *)packed_value;
    return pai->op;
  }
}

static mrb_value
mrb_io_uring_prep_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int domain, type, protocol = 0, flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "ii|iii", &domain, &type, &protocol, &flags, &sqe_flags);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->socket_val
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SOCKET);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_socket(sqe, (int) domain, (int) type, (int) protocol, (unsigned int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &flags, &sqe_flags);


  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->accept_val,
    mrb_io_uring->at_sock_val, sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_ACCEPT);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_accept(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  NULL, NULL,
  (int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_multishot_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &flags, &sqe_flags);


  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->multishot_accept_val,
    mrb_io_uring->at_sock_val, sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_ACCEPT);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_multishot_accept(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  NULL, NULL,
  (int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_connect(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, addrinfo;
  mrb_int sqe_flags = 0;
  mrb_get_args(mrb, "oS|i", &sock, &addrinfo, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,     self,
    mrb_io_uring->at_type_val,     mrb_io_uring->connect_val,
    mrb_io_uring->at_sock_val,     sock,
    mrb_io_uring->at_addrinfo_val, addrinfo
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_CONNECT);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_connect(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (const struct sockaddr *) RSTRING_PTR(addrinfo), RSTRING_LEN(addrinfo)
  );
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_recv(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int len = 0, flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|iii", &sock, &len, &flags, &sqe_flags);
  int sockfd = (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno"));
  if (len <= 0) {
    socklen_t optlen = sizeof(len);
    if (unlikely(getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &len, &optlen) != 0)) {
      mrb_sys_fail(mrb, "getsockopt");
    }
  }

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  mrb_value buf = mrb_str_new_capa(mrb, len);
  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->recv_val,
    mrb_io_uring->at_sock_val, sock,
    mrb_io_uring->at_buf_val,  buf
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_RECV);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_recv(sqe,
  sockfd,
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_splice(mrb_state *mrb, mrb_value self)
{
  mrb_value fd_in, fd_out;
  mrb_int off_in, off_out, nbytes, splice_flags, sqe_flags = 0;
  mrb_get_args(mrb, "oioiii|i", &fd_in, &off_in, &fd_out, &off_out, &nbytes, &splice_flags, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->splice_val,
    mrb_io_uring->at_sock_val, mrb_assoc_new(mrb, fd_in, fd_out)
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SPLICE);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_splice(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, fd_in,  MRB_TT_INTEGER, "Integer", "fileno")), off_in,
  (int) mrb_integer(mrb_convert_type(mrb, fd_out, MRB_TT_INTEGER, "Integer", "fileno")), off_out,
  (unsigned int) nbytes, (unsigned int) splice_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_send(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "oS|ii", &sock, &buf, &flags, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->send_val,
    mrb_io_uring->at_sock_val, sock,
    mrb_io_uring->at_buf_val,  buf,
    mrb_io_uring->buf_was_frozen_val, mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(buf))))
  };
  mrb_obj_freeze(mrb, buf);

  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SEND);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_send(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int how, sqe_flags = 0;
  mrb_get_args(mrb, "oi|i", &sock, &how, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->shutdown_val,
    mrb_io_uring->at_sock_val, sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SHUTDOWN);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_shutdown(sqe, (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")), (int) how);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_close(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int sqe_flags = 0;
  mrb_get_args(mrb, "o|i", &sock, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->close_val,
    mrb_io_uring->at_sock_val, sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_CLOSE);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_close(sqe, (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")));
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_add(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &poll_mask, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,       self,
    mrb_io_uring->at_type_val,       mrb_io_uring->poll_add_val,
    mrb_io_uring->at_sock_val,       sock,
    mrb_io_uring->at_poll_mask_val,  mrb_int_value(mrb, poll_mask)
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_POLL_ADD);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);


  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_prep_poll_add(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (unsigned int) poll_mask);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_multishot(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &poll_mask, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,       self,
    mrb_io_uring->at_type_val,       mrb_io_uring->poll_multishot_val,
    mrb_io_uring->at_sock_val,       sock,
    mrb_io_uring->at_poll_mask_val,  mrb_int_value(mrb, poll_mask)
  };

  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_POLL_MULTISHOT);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_poll_multishot(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (unsigned int) poll_mask);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_update(mrb_state *mrb, mrb_value self)
{
  mrb_value old_operation;
  mrb_int poll_mask, flags, sqe_flags = 0;
  mrb_get_args(mrb, "oii|i", &old_operation, &poll_mask, &flags, &sqe_flags);
  mrb_data_check_type(mrb, old_operation, &mrb_io_uring_operation_type);
  flags |= IORING_POLL_UPDATE_USER_DATA;
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,       self,
    mrb_io_uring->at_type_val,       mrb_io_uring->poll_update_val,
    mrb_io_uring->at_sock_val,       mrb_iv_get(mrb, old_operation, mrb_io_uring->at_sock_sym),
    mrb_io_uring->at_poll_mask_val,  mrb_int_value(mrb, poll_mask),
    mrb_io_uring->at_userdata_val,   mrb_iv_get(mrb, old_operation, mrb_io_uring->at_userdata_sym)
  };
  mrb_value new_operation;
  new_operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);

  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(new_operation), MRB_IORING_OP_POLL_UPDATE);
  mrb_data_init(new_operation, &encoded_operation, &mrb_io_uring_operation_type);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_poll_update(sqe,
  (uintptr_t) mrb_ptr(old_operation), (uintptr_t) mrb_ptr(new_operation),
  (unsigned int) poll_mask, (unsigned int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, new_operation, new_operation);
  mrb_hash_delete_key(mrb, mrb_io_uring->sqes, old_operation);

  return new_operation;
}

static mrb_value
mrb_io_uring_prep_openat2(mrb_state *mrb, mrb_value self)
{
  mrb_value path, directory = mrb_nil_value(), open_how = mrb_nil_value();
  mrb_int sqe_flags = 0;
  mrb_get_args(mrb, "S|ooi", &path, &directory, &open_how, &sqe_flags);
  int dfd = AT_FDCWD;
  if (!mrb_nil_p(directory)) {
    dfd = (int) mrb_integer(mrb_convert_type(mrb, directory, MRB_TT_INTEGER, "Integer", "fileno"));
  }
  if (mrb_nil_p(open_how)) {
    open_how = mrb_obj_new(mrb, mrb_class_get_under_id(mrb, mrb_class(mrb, self), mrb_intern_lit(mrb, "OpenHow")), 0, NULL);
  }

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,       self,
    mrb_io_uring->at_type_val,       mrb_io_uring->openat2_val,
    mrb_io_uring->at_path_val,       path,
    mrb_io_uring->at_directory_val,  directory,
    mrb_io_uring->at_open_how_val,   open_how,
    mrb_io_uring->path_was_frozen_val,   mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(path))))
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_OPENAT2);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);

  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_prep_openat2(sqe, dfd, mrb_string_value_cstr(mrb, &path), mrb_data_get_ptr(mrb, open_how, &mrb_io_uring_open_how_type));
  mrb_obj_freeze(mrb, path);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_read(mrb_state *mrb, mrb_value self)
{
  mrb_value file;
  mrb_int nbytes = 0, offset = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|iii", &file, &nbytes, &offset, &sqe_flags);
  int filefd = (int) mrb_integer(mrb_convert_type(mrb, file, MRB_TT_INTEGER, "Integer", "fileno"));
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  if (nbytes <= 0) {
    struct stat st;
    if (likely(fstat(filefd, &st)) == 0) {
        nbytes = st.st_size;
    } else {
      mrb_sys_fail(mrb, "fstat");
    }
  }

  mrb_value buf = mrb_str_new_capa(mrb, nbytes);
  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->read_val,
    mrb_io_uring->at_file_val, file,
    mrb_io_uring->at_buf_val,  buf
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_READ);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_read(sqe,
  filefd,
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (unsigned long long) offset);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);
  mrb_obj_freeze(mrb, buf);

  return operation;
}

static mrb_value
mrb_io_uring_prep_read_fixed(mrb_state *mrb, mrb_value self)
{
  mrb_value file;
  mrb_int offset = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &file, &offset, &sqe_flags);
  int fd = (int) mrb_integer(mrb_convert_type(mrb, file, MRB_TT_INTEGER, "Integer", "fileno"));

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_io_uring_buffer_t buffer_t = mrb_io_uring_buffer_get(mrb, mrb_io_uring);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,     self,
    mrb_io_uring->at_type_val,     mrb_io_uring->read_fixed_val,
    mrb_io_uring->at_file_val,     file,
    mrb_io_uring->at_buf_val,      buffer_t.buffer,
    mrb_io_uring->buf_index_val, mrb_int_value(mrb, buffer_t.index)
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_READ_FIXED);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_read_fixed(sqe,
    fd,
    RSTRING_PTR(buffer_t.buffer), RSTRING_CAPA(buffer_t.buffer) + 1,
    (unsigned long long) offset, buffer_t.index);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_write(mrb_state *mrb, mrb_value self)
{
  mrb_value file, buf;
  mrb_int offset, sqe_flags = 0;
  mrb_get_args(mrb, "oSi|i", &file, &buf, &offset, &sqe_flags);
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value argv[] = {
    mrb_io_uring->at_ring_val, self,
    mrb_io_uring->at_type_val, mrb_io_uring->write_val,
    mrb_io_uring->at_file_val, file,
    mrb_io_uring->at_buf_val,  buf,
    mrb_io_uring->buf_was_frozen_val, mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(buf))))
  };
  mrb_obj_freeze(mrb, buf);

  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_WRITE);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_write(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, file, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (__u64) offset);

  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);


  return operation;
}

static mrb_value
mrb_io_uring_prep_cancel(mrb_state *mrb, mrb_value self)
{
  mrb_value operation;
  mrb_int flags = IORING_ASYNC_CANCEL_ALL, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &operation, &flags, &sqe_flags);
  mrb_data_check_type(mrb, operation, &mrb_io_uring_operation_type);


  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,       self,
    mrb_io_uring->at_type_val,       mrb_io_uring->cancel_val,
    mrb_io_uring->at_operation_val,  operation
  };
  mrb_value cancel_operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_CANCEL);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_prep_cancel(sqe, mrb_ptr(operation), (int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, cancel_operation, cancel_operation);

  return cancel_operation;
}

static mrb_value
mrb_io_uring_prep_statx(mrb_state *mrb, mrb_value self)
{
  mrb_value path;
  mrb_value directory = mrb_nil_value();
  mrb_int flags = 0, mask = STATX_BASIC_STATS | STATX_BTIME, sqe_flags = 0;
  mrb_get_args(mrb, "S|oiio", &path, &directory, &flags, &mask, &sqe_flags);
  int dfd = AT_FDCWD;
  if(!mrb_nil_p(directory)) {
    dfd = mrb_integer(mrb_convert_type(mrb, directory, MRB_TT_INTEGER, "Integer", "fileno"));
  }

  struct statx *statxbuf = NULL;
  struct RData* statx_data = NULL;
  Data_Make_Struct(mrb, mrb_class_get_id(mrb, mrb_intern_lit(mrb, "Statx")), struct statx, &mrb_io_uring_statx_type, statxbuf, statx_data);
  mrb_value statx = mrb_obj_value(statx_data);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  mrb_value argv[] = {
    mrb_io_uring->at_ring_val,        self,
    mrb_io_uring->at_type_val,        mrb_io_uring->statx_val,
    mrb_io_uring->at_path_val,        path,
    mrb_io_uring->at_directory_val,   directory,
    mrb_io_uring->path_was_frozen_val,mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(path)))),
    mrb_io_uring->at_statx_val,      statx
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uint64_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_STATX);
  mrb_data_init(operation, &encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);

  io_uring_sqe_set_data64(sqe, encoded_operation);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_prep_statx(sqe, dfd, mrb_string_value_cstr(mrb, &path), flags, mask, statxbuf);
  mrb_obj_freeze(mrb, path);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return self;
}

static void
mrb_statx_set_intance_variables(mrb_state *mrb, mrb_value self, struct statx *stx)
{
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@mask"), mrb_int_value(mrb, stx->stx_mask));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@blksize"), mrb_int_value(mrb, stx->stx_blksize));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@attributes"), mrb_int_value(mrb, stx->stx_attributes));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@nlink"), mrb_int_value(mrb, stx->stx_nlink));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@uid"), mrb_int_value(mrb, stx->stx_uid));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@gid"), mrb_int_value(mrb, stx->stx_gid));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@mode"), mrb_int_value(mrb, stx->stx_mode));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ino"), mrb_int_value(mrb, stx->stx_ino));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@size"), mrb_int_value(mrb, stx->stx_size));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@blocks"), mrb_int_value(mrb, stx->stx_blocks));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@attributes_mask"), mrb_int_value(mrb, stx->stx_attributes_mask));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@atime_sec"), mrb_int_value(mrb, stx->stx_atime.tv_sec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@atime_nsec"), mrb_int_value(mrb, stx->stx_atime.tv_nsec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@btime_sec"), mrb_int_value(mrb, stx->stx_btime.tv_sec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@btime_nsec"), mrb_int_value(mrb, stx->stx_btime.tv_nsec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ctime_sec"), mrb_int_value(mrb, stx->stx_ctime.tv_sec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ctime_nsec"), mrb_int_value(mrb, stx->stx_ctime.tv_nsec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@mtime_sec"), mrb_int_value(mrb, stx->stx_mtime.tv_sec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@mtime_nsec"), mrb_int_value(mrb, stx->stx_mtime.tv_nsec));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@rdev_major"), mrb_int_value(mrb, stx->stx_rdev_major));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@rdev_minor"), mrb_int_value(mrb, stx->stx_rdev_minor));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@dev_major"), mrb_int_value(mrb, stx->stx_dev_major));
mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@dev_minor"), mrb_int_value(mrb, stx->stx_dev_minor));

#ifdef STATX_MNT_ID
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@mnt_id"), mrb_int_value(mrb, stx->stx_mnt_id));
#endif
#ifdef STATX_DIOALIGN
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@dio_mem_align"), mrb_int_value(mrb, stx->stx_dio_mem_align));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@dio_offset_align"), mrb_int_value(mrb, stx->stx_dio_offset_align));
#endif
}

static mrb_value
mrb_statx_for_statx(mrb_state *mrb, mrb_value self)
{
  mrb_statx_set_intance_variables(mrb, self, DATA_PTR(self));
  mrb_funcall_id(mrb, self, mrb_intern_lit(mrb, "convert_timestamps"), 0);

  return self;
}

static mrb_value
mrb_statx_initialize(mrb_state *mrb, mrb_value self)
{
  const char *path;
  mrb_value dirfd = mrb_nil_value();
  mrb_int flags = 0, mask = STATX_BASIC_STATS | STATX_BTIME;
  struct statx stx;
  memset(&stx, '\0', sizeof(stx));

  mrb_get_args(mrb, "z|oii", &path, &dirfd, &flags, &mask);
  int dfd = AT_FDCWD;
  if(!mrb_nil_p(dirfd)) {
    dfd = mrb_integer(mrb_convert_type(mrb, dirfd, MRB_TT_INTEGER, "Integer", "fileno"));
  }

  if (syscall(SYS_statx, dfd, path, flags, mask, &stx) < 0) {
    mrb_sys_fail(mrb, "statx");
  }

  return mrb_statx_for_statx(mrb, self);
}

static mrb_value
mrb_io_uring_process_cqe(mrb_state *mrb, mrb_io_uring_t *mrb_io_uring, struct io_uring_cqe *cqe)
{
  uint64_t userdata = io_uring_cqe_get_data64(cqe);
  mrb_value operation = mrb_obj_value(decode_operation(userdata));
  mrb_value res = mrb_int_value(mrb, cqe->res);
  mrb_iv_set(mrb, operation, mrb_io_uring->at_res_sym, res);
  mrb_iv_set(mrb, operation, mrb_io_uring->at_flags_sym, mrb_int_value(mrb, cqe->flags));

  if (likely(cqe->res >= 0)) {
    switch(decode_op(userdata)) {
      case MRB_IORING_OP_READ_FIXED: {
        mrb_value index_val = mrb_iv_get(mrb, operation, mrb_io_uring->buf_index_sym);
        mrb_int index = mrb_as_int(mrb, index_val);
        mrb_value buf = mrb_ary_ref(mrb, mrb_io_uring->buffers, index);
        if (likely(mrb_string_p(buf))) {
          struct RString *buf_str = mrb_str_ptr(buf);
          RSTR_UNSET_SINGLE_BYTE_FLAG(buf_str);
          RSTR_SET_LEN(buf_str, cqe->res);
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "but not found");
        }
      } break;
      case MRB_IORING_OP_ACCEPT:
      case MRB_IORING_OP_SOCKET:
        mrb_iv_set(mrb, operation, mrb_io_uring->at_sock_sym, res);
      break;
      case MRB_IORING_OP_READ:
      case MRB_IORING_OP_RECV: {
        mrb_value index_val = mrb_iv_get(mrb, operation, mrb_io_uring->buf_index_sym);
        if (unlikely(mrb_integer_p(index_val))) {
          mrb_raise(mrb, E_FROZEN_ERROR, "can't modify frozen Buffer");
        }
        mrb_value buf = mrb_iv_get(mrb, operation, mrb_io_uring->at_buf_sym);
        if (likely(mrb_string_p(buf))) {
          MRB_UNSET_FROZEN_FLAG(mrb_basic_ptr((buf)));
          mrb_str_resize(mrb, buf, cqe->res);
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "buf is not a string");
        }
      } break;
      case MRB_IORING_OP_WRITE:
      case MRB_IORING_OP_SEND: {
        mrb_value buf = mrb_iv_get(mrb, operation, mrb_io_uring->at_buf_sym);
        if (likely(mrb_string_p(buf))) {
          mrb_value buf_was_frozen = mrb_iv_get(mrb, operation, mrb_io_uring->buf_was_frozen_sym);
          if (!mrb_bool(buf_was_frozen)) {
            MRB_UNSET_FROZEN_FLAG(mrb_basic_ptr((buf)));
          }
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "buf is not a string");
        }
      } break;
      case MRB_IORING_OP_OPENAT2: {
        mrb_iv_set(mrb, operation, mrb_io_uring->at_file_sym, res);
        mrb_value path = mrb_iv_get(mrb, operation, mrb_io_uring->at_path_sym);
        if (likely(mrb_string_p(path))) {
          mrb_value path_was_frozen = mrb_iv_get(mrb, operation, mrb_io_uring->path_was_frozen_sym);
          if (!mrb_bool(path_was_frozen)) {
            MRB_UNSET_FROZEN_FLAG(mrb_basic_ptr((path)));
          }
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "path is not a string");
        }
      } break;
      case MRB_IORING_OP_STATX: {
        mrb_value statx = mrb_iv_get(mrb, operation, mrb_io_uring->at_statx_sym);
        mrb_value path = mrb_iv_get(mrb, operation, mrb_io_uring->at_path_sym);
        if (likely(mrb_string_p(path))) {
          mrb_value path_was_frozen = mrb_iv_get(mrb, operation, mrb_io_uring->path_was_frozen_sym);
          if (!mrb_bool(path_was_frozen)) {
            MRB_UNSET_FROZEN_FLAG(mrb_basic_ptr((path)));
          }
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "path is not a string");
        }
        mrb_statx_for_statx(mrb, statx);
      } break;
      default:
      break;
    }
  } else {
    mrb_value errno_val = mrb_fixnum_value(-cqe->res);
    mrb_iv_set(mrb, operation, mrb_io_uring->at_errno_sym, mrb_obj_new(mrb, mrb_class_get_id(mrb, mrb_intern_lit(mrb, "SystemCallError")), 1, &errno_val));
  }

  return operation;
}

static mrb_value
mrb_io_uring_iterate_over_cqes(mrb_state *mrb, mrb_io_uring_t *mrb_io_uring, mrb_value block, struct io_uring_cqe *cqe, int rc)
{
  struct mrb_jmpbuf* prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  unsigned int i = 0;

  MRB_TRY(&c_jmp)
  {
    mrb->jmp = &c_jmp;
    unsigned head;
    int arena_index = mrb_gc_arena_save(mrb);

    io_uring_for_each_cqe(&mrb_io_uring->ring, head, cqe) {
      mrb_value operation = mrb_io_uring_process_cqe(mrb, mrb_io_uring, cqe);
      mrb_yield(mrb, block, operation);
      if (decode_op(io_uring_cqe_get_data64(cqe)) == MRB_IORING_OP_READ_FIXED)  {
        mrb_io_uring_return_used_buffer(mrb, mrb_io_uring, operation);
      }
      if (!(cqe->flags & IORING_CQE_F_MORE)) {
        mrb_hash_delete_key(mrb, mrb_io_uring->sqes, operation);
      }
      mrb_gc_arena_restore(mrb, arena_index);
      i++;
    }
    io_uring_cq_advance(&mrb_io_uring->ring, i);
    mrb->jmp = prev_jmp;
  }
  MRB_CATCH(&c_jmp)
  {
    mrb->jmp = prev_jmp;
    io_uring_cq_advance(&mrb_io_uring->ring, i);
    MRB_THROW(mrb->jmp);
  }
  MRB_END_EXC(&c_jmp);

  return mrb_int_value(mrb, rc);
}

static mrb_value
mrb_io_uring_submit_and_wait_timeout(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_int wait_nr = 1;
  mrb_float timeout = -1.0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "|if&", &wait_nr, &timeout, &block);
  if(unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if(unlikely(mrb_type(block) != MRB_TT_PROC)) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }

  struct io_uring_cqe *cqe = NULL;
  int rc;
  if (timeout >= 0) {
    timeout += 1e-17; // we are adding this so ts can't become negative.
    struct __kernel_timespec ts = {
      .tv_sec  = timeout,
      .tv_nsec = (timeout - (mrb_int)(timeout)) * NSEC_PER_SEC
    };
    rc = io_uring_submit_and_wait_timeout(&mrb_io_uring->ring, &cqe, (unsigned) wait_nr, &ts, NULL);
  } else {
    rc = io_uring_submit_and_wait_timeout(&mrb_io_uring->ring, &cqe, (unsigned) wait_nr, NULL, NULL);
  }

  if (rc < 0) {
    errno = -rc;
    if (likely(errno == ETIME))
      return mrb_false_value();
    mrb_sys_fail(mrb, "io_uring_submit_and_wait_timeout");
  }

  return mrb_io_uring_iterate_over_cqes(mrb, mrb_io_uring, block, cqe, rc);
}

static __u64
mrb_io_uring_parse_flags_string(mrb_state *mrb, mrb_value flags_val)
{
  if (mrb_nil_p(flags_val)) {
    return 0;
  }
  const char *flags_str = mrb_string_value_cstr(mrb, &flags_val);

  __u64 flags = 0;
  mrb_bool seen_plus = FALSE;
  mrb_bool read_mode = FALSE;
  mrb_bool write_mode = FALSE;
  mrb_bool append_mode = FALSE;

  while (*flags_str) {
    char flag = *flags_str++;

    if (flag == '+') {
      if (unlikely(seen_plus)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must be at the end with no characters following, and only once");
      }
      seen_plus = TRUE;
    } else if (unlikely(seen_plus)) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must be at the end with no characters following");
    }

    switch (flag) {
      case '+':
        if (unlikely(!(read_mode || write_mode || append_mode))) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must follow 'r', 'w', or 'a'");
        }
        flags = (flags & ~O_ACCMODE) | O_RDWR;
        break;
      case 'D':
        if (unlikely(flags & O_DIRECTORY)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'D' specified more than once");
        }
        flags |= O_DIRECTORY;
        break;
      case 'P':
        if (unlikely(flags & O_PATH)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'P' specified more than once");
        }
        flags |= O_PATH;
        break;
      case 'a':
        if (unlikely(read_mode || write_mode || append_mode)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        append_mode = TRUE;
        flags |= O_WRONLY | O_CREAT | O_APPEND;
        break;
      case 'd':
        if (unlikely(flags & O_DIRECT)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'd' specified more than once");
        }
        flags |= O_DIRECT;
        break;
      case 'e':
        if (unlikely(flags & O_CLOEXEC)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'e' specified more than once");
        }
        flags |= O_CLOEXEC;
        break;
      case 'n':
        switch (*flags_str++) {
          case 'a':
            if (unlikely(flags & O_NOATIME)) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'na' specified more than once");
            }
            flags |= O_NOATIME;
            break;
          case 'b':
            if (unlikely(flags & O_NONBLOCK)) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'nb' specified more than once");
            }
            flags |= O_NONBLOCK;
            break;
          case 'c':
            if (unlikely(flags & O_NOCTTY)) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'nc' specified more than once");
            }
            flags |= O_NOCTTY;
            break;
          case 'f':
            if (unlikely(flags & O_NOFOLLOW)) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'nf' specified more than once");
            }
            flags |= O_NOFOLLOW;
            break;
          default:
            mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid flags string");
        }
        break;
      case 'r':
        if (unlikely(read_mode || write_mode || append_mode)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        read_mode = TRUE;
        flags |= O_RDONLY;
        break;
      case 's':
        if (unlikely(flags & O_SYNC)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 's' specified more than once");
        }
        flags |= O_SYNC;
        break;
      case 't':
        if (unlikely(flags & O_TMPFILE)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 't' specified more than once");
        }
        flags |= O_TMPFILE;
        break;
      case 'w':
        if (unlikely(read_mode || write_mode || append_mode)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        write_mode = TRUE;
        flags |= O_WRONLY | O_CREAT | O_TRUNC;
        break;
      default:
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid flags string");
    }
  }

  return flags;
}

static __u64 mrb_io_uring_parse_resolve_string(mrb_state *mrb, mrb_value resolve) {
  if (mrb_nil_p(resolve)) {
    return 0;
  }
  const char *resolve_str = mrb_string_value_cstr(mrb, &resolve);

  __u64 resolve_flags = 0;

  while (*resolve_str) {
    char flag = *resolve_str++;

    switch (flag) {
      case 'B':
#ifdef RESOLVE_BENEATH
        if (unlikely(resolve_flags & RESOLVE_BENEATH)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'B' specified more than once");
        }
        resolve_flags |= RESOLVE_BENEATH;
#else
        mrb_raise(mrb, E_ARGUMENT_ERROR, "RESOLVE_BENEATH is not supported");
#endif
        break;
      case 'C':
#ifdef RESOLVE_CACHED
        if (unlikely(resolve_flags & RESOLVE_CACHED)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'C' specified more than once");
        }
        resolve_flags |= RESOLVE_CACHED;
#else
        mrb_raise(mrb, E_ARGUMENT_ERROR, "RESOLVE_CACHED is not supported");
#endif
        break;
      case 'L':
#ifdef RESOLVE_NO_SYMLINKS
        if (unlikely(resolve_flags & RESOLVE_NO_SYMLINKS)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'L' specified more than once");
        }
        resolve_flags |= RESOLVE_NO_SYMLINKS;
#else
        mrb_raise(mrb, E_ARGUMENT_ERROR, "RESOLVE_NO_SYMLINKS is not supported");
#endif
        break;
      case 'R':
#ifdef RESOLVE_IN_ROOT
        if (unlikely(resolve_flags & RESOLVE_IN_ROOT)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'R' specified more than once");
        }
        resolve_flags |= RESOLVE_IN_ROOT;
#else
        mrb_raise(mrb, E_ARGUMENT_ERROR, "RESOLVE_IN_ROOT is not supported");
#endif
        break;
      case 'X':
#ifdef RESOLVE_NO_XDEV
        if (unlikely(resolve_flags & RESOLVE_NO_XDEV)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'X' specified more than once");
        }
        resolve_flags |= RESOLVE_NO_XDEV;
#else
        mrb_raise(mrb, E_ARGUMENT_ERROR, "RESOLVE_NO_XDEV is not supported");
#endif
        break;
      default:
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid resolve string");
    }
  }

  return resolve_flags;
}

static mrb_value
mrb_io_uring_open_how_init(mrb_state *mrb, mrb_value self)
{
  mrb_value flags = mrb_nil_value(), resolve = mrb_nil_value();
  mrb_int mode = -1;
  mrb_get_args(mrb, "|S!iS!", &flags, &mode, &resolve);

  struct open_how *how = mrb_realloc(mrb, DATA_PTR(self), sizeof(*how));
  mrb_data_init(self, how, &mrb_io_uring_open_how_type);

  how->flags = mrb_io_uring_parse_flags_string(mrb, flags);
  if (mode == -1) {
    how->mode = (how->flags & (O_CREAT | O_TMPFILE)) ? 0666 : 0;
  } else {
    how->mode = (unsigned long long) mode;
  }
  how->resolve = mrb_io_uring_parse_resolve_string(mrb, resolve);

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@flags"),    flags);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@mode"),     mrb_int_value(mrb, mode));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@resolve"),  resolve);

  return self;
}

static mrb_value
mrb_io_uring_operation_class_init(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_int argc;
  mrb_get_args(mrb, "*", &argv, &argc);

  if (unlikely(argc < 4 || argc % 2 != 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "expecting an even number of arguments; and at least four");
  }

  for (mrb_int i = 0; i < argc;) {
    mrb_value key = argv[i++];
    if (unlikely(!mrb_symbol_p(key))) {
      mrb_raise(mrb, E_TYPE_ERROR, "expected symbol for key");
    }

    mrb_iv_set(mrb, self, mrb_symbol(key), argv[i++]);
  }

  return self;
}

static mrb_value
mrb_io_uring_operation_to_io(mrb_state *mrb, mrb_value self)
{
  mrb_value sock_obj, file_obj;

  sock_obj = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@sock"));
  file_obj = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@file"));

  if (!mrb_nil_p(sock_obj)) {
    struct RClass *socket_class = NULL;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int sockfd = mrb_integer(mrb_convert_type(mrb, sock_obj, MRB_TT_INTEGER, "Integer", "fileno"));

    int is_accept;
    socklen_t optlen = sizeof(is_accept);

    if (unlikely(getsockopt(sockfd, SOL_SOCKET, SO_ACCEPTCONN, &is_accept, &optlen) == -1)) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to get socket options");
    }

    if (unlikely(getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) == -1)) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to get socket name");
    }

    switch (addr.ss_family) {
      case AF_UNIX:
        socket_class = is_accept ? mrb_class_get_id(mrb, mrb_intern_lit(mrb, "UNIXServer")) : mrb_class_get_id(mrb, mrb_intern_lit(mrb, "UNIXSocket"));
        break;
      case AF_INET:
      case AF_INET6:
        if (is_accept) {
          socket_class = mrb_class_get_id(mrb, mrb_intern_lit(mrb, "TCPServer"));
        } else {
          int socktype;
          if (unlikely(getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen) == -1)) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "failed to get socket type");
          }
          switch (socktype) {
            case SOCK_STREAM:
              socket_class = mrb_class_get_id(mrb, mrb_intern_lit(mrb, "TCPSocket"));
              break;
            case SOCK_DGRAM:
              socket_class = mrb_class_get_id(mrb, mrb_intern_lit(mrb, "UDPSocket"));
              break;
            default: {
              socket_class = mrb_class_get_id(mrb, mrb_intern_lit(mrb, "IPSocket"));
            }
          }
        }
        break;
      default: {
        socket_class = mrb_class_get_id(mrb, mrb_intern_lit(mrb, "BasicSocket"));
      }
    }

    mrb_value socket_obj = mrb_funcall_id(mrb, mrb_obj_value(socket_class), mrb_intern_lit(mrb, "for_fd"), 1, sock_obj);
    (void)mrb_io_fileno(mrb, socket_obj);
    ((struct mrb_io *)DATA_PTR(socket_obj))->close_fd = 0;
    return socket_obj;

  } else if (!mrb_nil_p(file_obj)) {
    file_obj = mrb_obj_new(mrb, mrb_class_get(mrb, "File"), 1, &file_obj);
    (void)mrb_io_fileno(mrb, file_obj);
    ((struct mrb_io *)DATA_PTR(file_obj))->close_fd = 0;
    return file_obj;
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid @sock or @file descriptor");
  }

}

static mrb_value
mrb_uring_readable(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  if (likely(mrb_integer_p(res)))
    return mrb_bool_value(mrb_integer(res) & POLLIN);
  return mrb_nil_value();
}

static mrb_value
mrb_uring_writable(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  if (likely(mrb_integer_p(res)))
    return mrb_bool_value(mrb_integer(res) & POLLOUT);
  return mrb_nil_value();
}

static void
initialize_can_use_buffers_once()
{
  struct io_uring ring = {0};
  struct io_uring_params params = {0};
  int ret = io_uring_queue_init_params(1, &ring, &params);
  if (ret == 0) {
    ret = io_uring_register_buffers_sparse(&ring, 1);
    if (ret == 0) {
      can_use_buffers = TRUE;
    }
  }
  io_uring_queue_exit(&ring);
}

static void
initialize_high_bits_check_once(mrb_state *mrb)
{
  void *ptr = mrb_malloc_simple(mrb, 1);

  if (likely(ptr)) {
    uintptr_t address = (uintptr_t)ptr;
    can_use_high_bits = !(address & 0xFFFF000000000000ULL);

    mrb_free(mrb, ptr);
  } else {
    pthread_mutex_unlock(&mutex);
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

void
mrb_mruby_io_uring_gem_init(mrb_state* mrb)
{
  pthread_mutex_lock(&mutex);
  if (init_once_done == FALSE) {
    init_once_done = TRUE;
    initialize_can_use_buffers_once();
    if (can_use_buffers) {
      page_size = sysconf(_SC_PAGESIZE);
      if (page_size == 0) {
        mrb_bug(mrb, "broken linux distro, returns a page size of 0");
      }
    }
    initialize_high_bits_check_once(mrb);
  }
  pthread_mutex_unlock(&mutex);

  struct RClass *io_uring_class, *io_uring_error_class, *io_uring_op_class, *io_uring_open_how_class;

  io_uring_class = mrb_define_class_under_id(mrb, mrb_class_get_id(mrb, mrb_intern_lit(mrb, "IO")), mrb_intern_lit(mrb, "Uring"), mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "initialize"),              mrb_io_uring_queue_init_params,       MRB_ARGS_OPT(2));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "submit"),                  mrb_io_uring_submit,                  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_socket"),             mrb_io_uring_prep_socket,             MRB_ARGS_ARG(2, 3));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_connect"),            mrb_io_uring_prep_connect,            MRB_ARGS_ARG(2, 1));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_accept"),             mrb_io_uring_prep_accept,             MRB_ARGS_ARG(1, 2));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_multishot_accept"),   mrb_io_uring_prep_multishot_accept,   MRB_ARGS_ARG(1, 2));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_recv"),               mrb_io_uring_prep_recv,               MRB_ARGS_ARG(1, 3));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_splice"),             mrb_io_uring_prep_splice,             MRB_ARGS_ARG(6, 1));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_send"),               mrb_io_uring_prep_send,               MRB_ARGS_ARG(2, 2));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_shutdown"),           mrb_io_uring_prep_shutdown,           MRB_ARGS_ARG(2, 1));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_close"),              mrb_io_uring_prep_close,              MRB_ARGS_ARG(1, 1));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_poll_add"),           mrb_io_uring_prep_poll_add,           MRB_ARGS_ARG(1, 2));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_poll_multishot"),     mrb_io_uring_prep_poll_multishot,     MRB_ARGS_ARG(1, 2));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_poll_update"),        mrb_io_uring_prep_poll_update,        MRB_ARGS_ARG(3, 1));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_openat2"),            mrb_io_uring_prep_openat2,            MRB_ARGS_ARG(1, 3));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_statx"),              mrb_io_uring_prep_statx,              MRB_ARGS_ARG(1, 3));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_read"),               mrb_io_uring_prep_read,               MRB_ARGS_ARG(1, 3));
if (can_use_buffers) {
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "fixed_buffer_size"),       mrb_io_uring_get_fixed_buffer_size,   MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_read_fixed"),         mrb_io_uring_prep_read_fixed,         MRB_ARGS_ARG(1, 2));
}
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_write"),              mrb_io_uring_prep_write,              MRB_ARGS_ARG(3, 1));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "prep_cancel"),             mrb_io_uring_prep_cancel,             MRB_ARGS_ARG(1, 2));
  mrb_define_method_id(mrb, io_uring_class, mrb_intern_lit(mrb, "wait"),                    mrb_io_uring_submit_and_wait_timeout, MRB_ARGS_OPT(2)|MRB_ARGS_BLOCK());
  mrb_define_const_id (mrb, io_uring_class, mrb_intern_lit(mrb, "ASYNC_CANCEL_ALL"),        mrb_fixnum_value(IORING_ASYNC_CANCEL_ALL));
  mrb_define_const_id (mrb, io_uring_class, mrb_intern_lit(mrb, "ASYNC_CANCEL_FD"),         mrb_fixnum_value(IORING_ASYNC_CANCEL_FD));
  mrb_define_const_id (mrb, io_uring_class, mrb_intern_lit(mrb, "ASYNC_CANCEL_ANY"),        mrb_fixnum_value(IORING_ASYNC_CANCEL_ANY));
  mrb_define_const_id (mrb, io_uring_class, mrb_intern_lit(mrb, "ASYNC_CANCEL_FD_FIXED"),   mrb_fixnum_value(IORING_ASYNC_CANCEL_FD_FIXED));
  mrb_define_const_id (mrb, io_uring_class, mrb_intern_lit(mrb, "POLL_ADD_MULTI"),          mrb_fixnum_value(IORING_POLL_ADD_MULTI));
  mrb_define_const_id (mrb, io_uring_class, mrb_intern_lit(mrb, "POLL_UPDATE_EVENTS"),      mrb_fixnum_value(IORING_POLL_UPDATE_EVENTS));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "POLLERR"), mrb_fixnum_value(POLLERR));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "POLLHUP"), mrb_fixnum_value(POLLHUP));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "POLLIN"),  mrb_fixnum_value(POLLIN));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "POLLNVAL"),mrb_fixnum_value(POLLNVAL));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "POLLOUT"), mrb_fixnum_value(POLLOUT));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "POLLPRI"), mrb_fixnum_value(POLLPRI));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "SHUT_RD"), mrb_fixnum_value(SHUT_RD));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "SHUT_WR"), mrb_fixnum_value(SHUT_WR));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "SHUT_RDWR"), mrb_fixnum_value(SHUT_RDWR));
  mrb_define_const_id (mrb, mrb->kernel_module, mrb_intern_lit(mrb, "AT_FDCWD"), mrb_fixnum_value(AT_FDCWD));

  io_uring_error_class = mrb_define_class_under_id(mrb, io_uring_class, mrb_intern_lit(mrb, "Error"), mrb->eStandardError_class);
  mrb_define_class_under(mrb, io_uring_class, "SQRingFullError",  io_uring_error_class);

  io_uring_open_how_class = mrb_define_class_under_id(mrb, io_uring_class, mrb_intern_lit(mrb, "OpenHow"), mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_open_how_class, MRB_TT_CDATA);
  mrb_define_method_id(mrb, io_uring_open_how_class, mrb_intern_lit(mrb, "initialize"), mrb_io_uring_open_how_init, MRB_ARGS_OPT(3));

  struct RClass *statx_class = mrb_define_class(mrb, "Statx", mrb->object_class);
  MRB_SET_INSTANCE_TT(statx_class, MRB_TT_CDATA);

  mrb_define_method(mrb, statx_class, "initialize", mrb_statx_initialize, MRB_ARGS_ARG(1, 3));

  /* Define constants for Statx */
#ifdef STATX_TYPE
  mrb_define_const(mrb, statx_class, "TYPE", mrb_int_value(mrb, STATX_TYPE));
#endif
#ifdef STATX_MODE
  mrb_define_const(mrb, statx_class, "MODE", mrb_int_value(mrb, STATX_MODE));
#endif
#ifdef STATX_NLINK
  mrb_define_const(mrb, statx_class, "NLINK", mrb_int_value(mrb, STATX_NLINK));
#endif
#ifdef STATX_UID
  mrb_define_const(mrb, statx_class, "UID", mrb_int_value(mrb, STATX_UID));
#endif
#ifdef STATX_GID
  mrb_define_const(mrb, statx_class, "GID", mrb_int_value(mrb, STATX_GID));
#endif
#ifdef STATX_ATIME
  mrb_define_const(mrb, statx_class, "ATIME", mrb_int_value(mrb, STATX_ATIME));
#endif
#ifdef STATX_MTIME
  mrb_define_const(mrb, statx_class, "MTIME", mrb_int_value(mrb, STATX_MTIME));
#endif
#ifdef STATX_CTIME
  mrb_define_const(mrb, statx_class, "CTIME", mrb_int_value(mrb, STATX_CTIME));
#endif
#ifdef STATX_INO
  mrb_define_const(mrb, statx_class, "INO", mrb_int_value(mrb, STATX_INO));
#endif
#ifdef STATX_SIZE
  mrb_define_const(mrb, statx_class, "SIZE", mrb_int_value(mrb, STATX_SIZE));
#endif
#ifdef STATX_BLOCKS
  mrb_define_const(mrb, statx_class, "BLOCKS", mrb_int_value(mrb, STATX_BLOCKS));
#endif
#ifdef STATX_BASIC_STATS
  mrb_define_const(mrb, statx_class, "BASIC_STATS", mrb_int_value(mrb, STATX_BASIC_STATS));
#endif
#ifdef STATX_BTIME
  mrb_define_const(mrb, statx_class, "BTIME", mrb_int_value(mrb, STATX_BTIME));
#endif
#ifdef STATX_ALL
  mrb_define_const(mrb, statx_class, "ALL", mrb_int_value(mrb, STATX_ALL));
#endif
#ifdef STATX_MNT_ID
  mrb_define_const(mrb, statx_class, "MNT_ID", mrb_int_value(mrb, STATX_MNT_ID));
#endif
#ifdef STATX_DIOALIGN
  mrb_define_const(mrb, statx_class, "DIOALIGN", mrb_int_value(mrb, STATX_DIOALIGN));
#endif

  /* Define other constants in Kernel */
#ifdef AT_EMPTY_PATH
  mrb_define_const(mrb, mrb->kernel_module, "AT_EMPTY_PATH", mrb_int_value(mrb, AT_EMPTY_PATH));
#endif
#ifdef AT_NO_AUTOMOUNT
  mrb_define_const(mrb, mrb->kernel_module, "AT_NO_AUTOMOUNT", mrb_int_value(mrb, AT_NO_AUTOMOUNT));
#endif
#ifdef AT_SYMLINK_NOFOLLOW
  mrb_define_const(mrb, mrb->kernel_module, "AT_SYMLINK_NOFOLLOW", mrb_int_value(mrb, AT_SYMLINK_NOFOLLOW));
#endif
#ifdef AT_STATX_SYNC_AS_STAT
  mrb_define_const(mrb, mrb->kernel_module, "AT_STATX_SYNC_AS_STAT", mrb_int_value(mrb, AT_STATX_SYNC_AS_STAT));
#endif
#ifdef AT_STATX_FORCE_SYNC
  mrb_define_const(mrb, mrb->kernel_module, "AT_STATX_FORCE_SYNC", mrb_int_value(mrb, AT_STATX_FORCE_SYNC));
#endif
#ifdef AT_STATX_DONT_SYNC
  mrb_define_const(mrb, mrb->kernel_module, "AT_STATX_DONT_SYNC", mrb_int_value(mrb, AT_STATX_DONT_SYNC));
#endif

  io_uring_op_class = mrb_define_class_under_id(mrb, io_uring_class, mrb_intern_lit(mrb, "Operation"), mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_op_class, MRB_TT_CDATA);
  mrb_define_method_id(mrb, io_uring_op_class, mrb_intern_lit(mrb, "initialize"),           mrb_io_uring_operation_class_init, MRB_ARGS_ANY());
  mrb_define_const_id (mrb, io_uring_op_class, mrb_intern_lit(mrb, "CQE_F_BUFFER"),         mrb_fixnum_value(IORING_CQE_F_BUFFER));
  mrb_define_const_id (mrb, io_uring_op_class, mrb_intern_lit(mrb, "CQE_F_MORE"),           mrb_fixnum_value(IORING_CQE_F_MORE));
  mrb_define_const_id (mrb, io_uring_op_class, mrb_intern_lit(mrb, "CQE_F_SOCK_NONEMPTY"),  mrb_fixnum_value(IORING_CQE_F_SOCK_NONEMPTY));
  mrb_define_const_id (mrb, io_uring_op_class, mrb_intern_lit(mrb, "CQE_F_NOTIF"),          mrb_fixnum_value(IORING_CQE_F_NOTIF));
  mrb_define_const_id (mrb, io_uring_op_class, mrb_intern_lit(mrb, "SQE_IO_LINK"),          mrb_fixnum_value(IOSQE_IO_LINK));
  mrb_define_method_id(mrb, io_uring_op_class, mrb_intern_lit(mrb, "to_io"),                mrb_io_uring_operation_to_io,  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, mrb_intern_lit(mrb, "readable?"),            mrb_uring_readable, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, mrb_intern_lit(mrb, "writable?"),            mrb_uring_writable, MRB_ARGS_NONE());
}

void mrb_mruby_io_uring_gem_final(mrb_state* mrb) {}
