#include "mrb_io_uring.h"
#include "mruby/value.h"

static mrb_value
mrb_io_uring_queue_init_params(mrb_state *mrb, mrb_value self)
{
  mrb_int fixed_buffer_size = MRB_IORING_DEFAULT_FIXED_BUFFER_SIZE, entries = 2048, flags = 0;
  mrb_get_args(mrb, "|iii", &fixed_buffer_size, &entries, &flags);

  if (unlikely(entries <= 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too few entries");
  }
  entries = MIN(entries, 32768);
  if (unlikely(flags < 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "flags mustn't be negative");
  }
  flags |= IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_COOP_TASKRUN|IORING_SETUP_DEFER_TASKRUN;

  struct rlimit limit;
  if (unlikely(getrlimit(RLIMIT_MEMLOCK, &limit) == -1)) {
    mrb_sys_fail(mrb, "getrlimit");
  }
  limit.rlim_cur = limit.rlim_max;
  if (unlikely(setrlimit(RLIMIT_MEMLOCK, &limit) == -1)) {
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
    mrb_iv_set(mrb, self, MRB_SYM(sqes), mrb_io_uring->sqes);
    mrb_io_uring->operation_class = mrb_class_get_under_id(mrb, mrb_class(mrb, self), MRB_SYM(Operation));

    if (can_use_buffers) {
      if (fixed_buffer_size < page_size) {
        fixed_buffer_size = page_size;
      } else if (fixed_buffer_size > (1 << 30)) {
        fixed_buffer_size = (1 << 30);
      } else if (fixed_buffer_size % page_size != 0) {
        fixed_buffer_size = (fixed_buffer_size / page_size) * page_size;
      }
      unsigned int max_buffers = MIN(limit.rlim_max / fixed_buffer_size, 16384);
      ret = io_uring_register_buffers_sparse(&mrb_io_uring->ring, max_buffers);
      if (likely(ret == 0)) {
        mrb_io_uring->fixed_buffer_size = (size_t) fixed_buffer_size;
        mrb_io_uring->buffers = mrb_ary_new(mrb);
        mrb_iv_set(mrb, self, MRB_SYM(buffers), mrb_io_uring->buffers);

        /* NEW: free_pool as a Hash instead of Array */
        mrb_io_uring->free_pool = mrb_hash_new(mrb);
        mrb_iv_set(mrb, self, MRB_SYM(free_pool), mrb_io_uring->free_pool);
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
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  return mrb_int_value(mrb, mrb_io_uring->fixed_buffer_size);
}

struct pop_result {
  mrb_value key;
  mrb_bool found;
};

static int
pop_first_cb(mrb_state *mrb, mrb_value key, mrb_value val, void *ud)
{
  pop_result *res = static_cast<pop_result*>(ud);
  res->key   = key;
  res->found = TRUE;
  return 1; // stop iteration immediately
}

static mrb_io_uring_fixed_buffer_t
mrb_io_uring_fixed_buffer_get(mrb_state *mrb, mrb_io_uring_t *mrb_io_uring)
{
  // Try to reuse a buffer from the free_pool
  if (mrb_hash_size(mrb, mrb_io_uring->free_pool) > 0) {
    pop_result res{};
    mrb_hash_foreach(mrb, mrb_hash_ptr(mrb_io_uring->free_pool), pop_first_cb, &res);

    if (res.found) {
      mrb_hash_delete_key(mrb, mrb_io_uring->free_pool, res.key);
      mrb_int index = mrb_as_int(mrb, res.key);
      mrb_io_uring_fixed_buffer_t result = {
        index,
        mrb_ary_ref(mrb, mrb_io_uring->buffers, index)
      };
      return result;
    }
  }

  // No free buffer available, allocate a new one
  mrb_int num_buffers = RARRAY_LEN(mrb_io_uring->buffers);
  mrb_value buffer = mrb_str_new_capa(mrb, mrb_io_uring->fixed_buffer_size - 1);
  mrb_obj_freeze(mrb, buffer);

  struct iovec iovec = { RSTRING_PTR(buffer), mrb_io_uring->fixed_buffer_size };
  int ret = io_uring_register_buffers_update_tag(&mrb_io_uring->ring,
                                                 num_buffers,
                                                 &iovec,
                                                 NULL,
                                                 1);
  if (likely(ret == 1)) {
    mrb_io_uring_fixed_buffer_t result = { num_buffers, buffer };
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
  mrb_data_check_type(mrb, operation, &mrb_io_uring_operation_type);
  mrb_value index_val = mrb_iv_get(mrb, operation, MRB_SYM(buf_index));
  mrb_int index = mrb_as_int(mrb, index_val);

  if (unlikely(!mrb_string_p(mrb_ary_ref(mrb, mrb_io_uring->buffers, index)))) {
    mrb_raise(mrb, E_TYPE_ERROR, "buf not found");
  }

  /* NEW: push into free_pool (Hash) instead of Array */
  mrb_hash_set(mrb, mrb_io_uring->free_pool, index_val, mrb_true_value());

  mrb_iv_remove(mrb, operation, MRB_SYM(buf));
  mrb_iv_remove(mrb, operation, MRB_SYM(buf_index));
}

static mrb_value
mrb_io_uring_return_used_buffer_m(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value operation;
  mrb_get_args(mrb, "o", &operation);
  mrb_io_uring_return_used_buffer(mrb, mrb_io_uring, operation);
  return self;
}

static mrb_value
mrb_io_uring_submit(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
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

static mrb_value
mrb_io_uring_prep_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int domain, type, protocol = 0, flags = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "ii|iii&", &domain, &type, &protocol, &flags, &sqe_flags, &block);

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(socket)),
    mrb_symbol_value(MRB_SYM(block)),  block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SOCKET);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_socket(sqe, (int) domain, (int) type, (int) protocol, (unsigned int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_build_socket(mrb_state *mrb, mrb_value self)
{
  mrb_sym type_sym;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "n|ii&", &type_sym, &flags, &sqe_flags, &block);
  mrb_int domain, type, protocol = 0;

  switch (type_sym) {
    case MRB_SYM(tcp):
      domain = AF_INET;
      type = SOCK_STREAM;
    break;
    case MRB_SYM(udp):
      domain = AF_INET;
      type = SOCK_DGRAM;
    break;
    default:
      mrb_raise(mrb, E_ARGUMENT_ERROR, "unknown socket type");
      return mrb_undef_value();
  }

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(socket)),
    mrb_symbol_value(MRB_SYM(block)),  block,
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SOCKET);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_socket(sqe, (int) domain, (int) type, (int) protocol, (unsigned int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, addrinfo;
  mrb_int sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oS|i&", &sock, &addrinfo, &sqe_flags, &block);

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(bind)),
    mrb_symbol_value(MRB_IVSYM(sock)), sock,
    mrb_symbol_value(MRB_SYM(addrinfo)), addrinfo,
    mrb_symbol_value(MRB_SYM(block)),  block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_BIND);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_bind(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
  (struct sockaddr *) RSTRING_PTR(addrinfo), RSTRING_LEN(addrinfo)
  );
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);
  return operation;
}

static mrb_value
mrb_io_uring_prep_listen(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int backlog = SOMAXCONN, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &sock, &backlog, &sqe_flags, &block);

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(listen)),
    mrb_symbol_value(MRB_IVSYM(sock)), sock,
    mrb_symbol_value(MRB_SYM(block)), block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_LISTEN);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_listen(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
  (int) backlog);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &sock, &flags, &sqe_flags, &block);

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(accept)),
    mrb_symbol_value(MRB_IVSYM(sock)), sock,
    mrb_symbol_value(MRB_SYM(block)), block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_ACCEPT);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_accept(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
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
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &sock, &flags, &sqe_flags, &block);

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),  self,
    mrb_symbol_value(MRB_IVSYM(type)),  mrb_symbol_value(MRB_SYM(multishot_accept)),
    mrb_symbol_value(MRB_IVSYM(sock)),  sock,
    mrb_symbol_value(MRB_SYM(block)),   block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_ACCEPT);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_multishot_accept(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
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
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oS|i&", &sock, &addrinfo, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),     self,
    mrb_symbol_value(MRB_IVSYM(type)),     mrb_symbol_value(MRB_SYM(connect)),
    mrb_symbol_value(MRB_IVSYM(sock)),     sock,
    mrb_symbol_value(MRB_SYM(addrinfo)),  addrinfo,
    mrb_symbol_value(MRB_SYM(block)),     block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_CONNECT);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_connect(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
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
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|iii&", &sock, &len, &flags, &sqe_flags, &block);
  int sockfd = (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno)));
  if (len <= 0) {
    socklen_t optlen = sizeof(len);
    if (unlikely(getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &len, &optlen) != 0)) {
      mrb_sys_fail(mrb, "getsockopt");
    }
  }

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value buf = mrb_str_new_capa(mrb, len);
  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(recv)),
    mrb_symbol_value(MRB_IVSYM(sock)), sock,
    mrb_symbol_value(MRB_SYM(buf)),  buf,
    mrb_symbol_value(MRB_SYM(block)), block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_RECV);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
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
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oioiii|i&", &fd_in, &off_in, &fd_out, &off_out, &nbytes, &splice_flags, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(splice)),
    mrb_symbol_value(MRB_IVSYM(splice_socks)), mrb_assoc_new(mrb, fd_in, fd_out),
    mrb_symbol_value(MRB_SYM(block)), block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SPLICE);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_splice(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, fd_in,  MRB_TT_INTEGER, MRB_SYM(fileno))), off_in,
  (int) mrb_integer(mrb_type_convert(mrb, fd_out, MRB_TT_INTEGER, MRB_SYM(fileno))), off_out,
  (unsigned int) nbytes, (unsigned int) splice_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_send(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oS|ii&", &sock, &buf, &flags, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(send)),
    mrb_symbol_value(MRB_IVSYM(sock)), sock,
    mrb_symbol_value(MRB_SYM(buf)),  buf,
    mrb_symbol_value(MRB_SYM(buf_was_frozen)), mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(buf)))),
    mrb_symbol_value(MRB_SYM(block)), block
  };
  mrb_obj_freeze(mrb, buf);

  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SEND);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_send(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
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
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oi|i&", &sock, &how, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(shutdown)),
    mrb_symbol_value(MRB_IVSYM(sock)), sock,
    mrb_symbol_value(MRB_SYM(block)), block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_SHUTDOWN);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_shutdown(sqe, (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))), (int) how);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_close(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|i&", &sock, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)), self,
    mrb_symbol_value(MRB_IVSYM(type)), mrb_symbol_value(MRB_SYM(close)),
    mrb_symbol_value(MRB_IVSYM(sock)), sock,
    mrb_symbol_value(MRB_SYM(block)), block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_CLOSE);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_close(sqe, (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))));
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_add(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &sock, &poll_mask, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),       self,
    mrb_symbol_value(MRB_IVSYM(type)),       mrb_symbol_value(MRB_SYM(poll_add)),
    mrb_symbol_value(MRB_IVSYM(sock)),       sock,
    mrb_symbol_value(MRB_IVSYM(poll_mask)),  mrb_int_value(mrb, poll_mask),
    mrb_symbol_value(MRB_SYM(block)),       block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_POLL_ADD);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_prep_poll_add(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
  (unsigned int) poll_mask);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_multishot(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &sock, &poll_mask, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),       self,
    mrb_symbol_value(MRB_IVSYM(type)),       mrb_symbol_value(MRB_SYM(poll_multishot)),
    mrb_symbol_value(MRB_IVSYM(sock)),       sock,
    mrb_symbol_value(MRB_IVSYM(poll_mask)),  mrb_int_value(mrb, poll_mask),
    mrb_symbol_value(MRB_SYM(block)),       block
  };

  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_POLL_MULTISHOT);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_poll_multishot(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, sock, MRB_TT_INTEGER, MRB_SYM(fileno))),
  (unsigned int) poll_mask);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_update(mrb_state *mrb, mrb_value self)
{
  mrb_value old_operation;
  mrb_int poll_mask, flags, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oii|i&", &old_operation, &poll_mask, &flags, &sqe_flags, &block);
  mrb_data_check_type(mrb, old_operation, &mrb_io_uring_operation_type);
  flags |= IORING_POLL_UPDATE_USER_DATA;
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),       self,
    mrb_symbol_value(MRB_IVSYM(type)),       mrb_symbol_value(MRB_SYM(poll_update)),
    mrb_symbol_value(MRB_IVSYM(sock)),       mrb_iv_get(mrb, old_operation, MRB_IVSYM(sock)),
    mrb_symbol_value(MRB_IVSYM(poll_mask)),  mrb_int_value(mrb, poll_mask),
    mrb_symbol_value(MRB_IVSYM(userdata)),   mrb_iv_get(mrb, old_operation, MRB_IVSYM(userdata)),
    mrb_symbol_value(MRB_SYM(block)),       block
  };
  mrb_value new_operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);

  uint64_t old_encoded_operation = (uint64_t) mrb_data_get_ptr(mrb, old_operation, &mrb_io_uring_operation_type);
  uint64_t new_encoded_operation = encode_operation_op(mrb, mrb_ptr(new_operation), MRB_IORING_OP_POLL_UPDATE);
  mrb_data_init(new_operation, (void *) new_encoded_operation, &mrb_io_uring_operation_type);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data64(sqe, new_encoded_operation);
  io_uring_prep_poll_update(sqe,
    old_encoded_operation, new_encoded_operation,
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
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "S|ooi&", &path, &directory, &open_how, &sqe_flags, &block);
  int dfd = AT_FDCWD;
  if (!mrb_nil_p(directory)) {
    dfd = (int) mrb_integer(mrb_type_convert(mrb, directory, MRB_TT_INTEGER, MRB_SYM(fileno)));
  }
  if (mrb_nil_p(open_how)) {
    open_how = mrb_obj_new(mrb, mrb_class_get_id(mrb, MRB_SYM(OpenHow)), 0, NULL);
  }

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),          self,
    mrb_symbol_value(MRB_IVSYM(type)),          mrb_symbol_value(MRB_SYM(openat2)),
    mrb_symbol_value(MRB_SYM(path)),            path,
    mrb_symbol_value(MRB_IVSYM(directory)),     directory,
    mrb_symbol_value(MRB_SYM(open_how)),        open_how,
    mrb_symbol_value(MRB_SYM(path_was_frozen)),mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(path)))),
    mrb_symbol_value(MRB_SYM(block)),          block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_OPENAT2);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);

  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_prep_openat2(sqe, dfd, RSTRING_CSTR(mrb, path), DATA_CHECK_GET_PTR(mrb, open_how, &mrb_io_uring_open_how_type, struct open_how));
  mrb_obj_freeze(mrb, path);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_read(mrb_state *mrb, mrb_value self)
{
  mrb_value file;
  mrb_int nbytes = 0, offset = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|iii&", &file, &nbytes, &offset, &sqe_flags, &block);
  int filefd = (int) mrb_integer(mrb_type_convert(mrb, file, MRB_TT_INTEGER, MRB_SYM(fileno)));
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  if (nbytes <= 0) {
    struct stat st;
    if (likely(fstat(filefd, &st) == 0)) {
      nbytes = st.st_size;
    } else {
      mrb_sys_fail(mrb, "fstat");
    }
  }

  mrb_value buf = mrb_str_new_capa(mrb, nbytes);
  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),  self,
    mrb_symbol_value(MRB_IVSYM(type)),  mrb_symbol_value(MRB_SYM(read)),
    mrb_symbol_value(MRB_IVSYM(file)),  file,
    mrb_symbol_value(MRB_SYM(buf)),     buf,
    mrb_symbol_value(MRB_SYM(block)),  block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_READ);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_read(sqe,
  filefd,
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (unsigned long long) offset);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_read_fixed(mrb_state *mrb, mrb_value self)
{
  mrb_value file;
  mrb_int offset = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &file, &offset, &sqe_flags, &block);
  int fd = (int) mrb_integer(mrb_type_convert(mrb, file, MRB_TT_INTEGER, MRB_SYM(fileno)));

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_io_uring_fixed_buffer_t buffer_t = mrb_io_uring_fixed_buffer_get(mrb, mrb_io_uring);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),    self,
    mrb_symbol_value(MRB_IVSYM(type)),    mrb_symbol_value(MRB_SYM(read_fixed)),
    mrb_symbol_value(MRB_IVSYM(file)),    file,
    mrb_symbol_value(MRB_SYM(buf)),       buffer_t.buffer,
    mrb_symbol_value(MRB_SYM(buf_index)), mrb_int_value(mrb, buffer_t.index),
    mrb_symbol_value(MRB_SYM(block)),     block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_READ_FIXED);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
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
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oSi|i&", &file, &buf, &offset, &sqe_flags, &block);
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),  self,
    mrb_symbol_value(MRB_IVSYM(type)),  mrb_symbol_value(MRB_SYM(write)),
    mrb_symbol_value(MRB_IVSYM(file)),  file,
    mrb_symbol_value(MRB_SYM(buf)),     buf,
    mrb_symbol_value(MRB_SYM(buf_was_frozen)), mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(buf)))),
    mrb_symbol_value(MRB_SYM(block)),  block
  };
  mrb_obj_freeze(mrb, buf);

  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_WRITE);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_write(sqe,
  (int) mrb_integer(mrb_type_convert(mrb, file, MRB_TT_INTEGER, MRB_SYM(fileno))),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (__u64) offset);

  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);


  return operation;
}

static mrb_value
mrb_io_uring_prep_write_fixed(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value file, read_operation;
  mrb_int offset = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "oo|ii&", &file, &read_operation, &offset, &sqe_flags, &block);
  mrb_data_check_type(mrb, read_operation, &mrb_io_uring_operation_type);
  int fd = (int) mrb_integer(mrb_type_convert(mrb, file, MRB_TT_INTEGER, MRB_SYM(fileno)));
  mrb_value index_val = mrb_iv_get(mrb, read_operation, MRB_SYM(buf_index));
  mrb_int index = mrb_as_int(mrb, index_val);
  mrb_value buf = mrb_ary_ref(mrb, mrb_io_uring->buffers, index);
  if (unlikely(!mrb_string_p(buf))) {
    mrb_raise(mrb, E_TYPE_ERROR, "buf not found");
  }

  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),    self,
    mrb_symbol_value(MRB_IVSYM(type)),    mrb_symbol_value(MRB_SYM(write_fixed)),
    mrb_symbol_value(MRB_IVSYM(file)),    file,
    mrb_symbol_value(MRB_SYM(buf)),       buf,
    mrb_symbol_value(MRB_SYM(buf_index)), index_val,
    mrb_symbol_value(MRB_SYM(block)),     block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_WRITE_FIXED);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_write_fixed(sqe,
    fd,
    RSTRING_PTR(buf), RSTRING_LEN(buf),
    (unsigned long long) offset, index);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_unlinkat(mrb_state *mrb, mrb_value self)
{
  mrb_value path, directory = mrb_nil_value();
  mrb_int flags = 0, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "S|oi&", &path, &directory, &flags, &sqe_flags, &block);
  int dfd = AT_FDCWD;
  if (!mrb_nil_p(directory)) {
    dfd = (int) mrb_integer(mrb_type_convert(mrb, directory, MRB_TT_INTEGER, MRB_SYM(fileno)));
  }

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),       self,
    mrb_symbol_value(MRB_IVSYM(type)),       mrb_symbol_value(MRB_SYM(unlinkat)),
    mrb_symbol_value(MRB_SYM(path)),         path,
    mrb_symbol_value(MRB_IVSYM(directory)),  directory,
    mrb_symbol_value(MRB_SYM(path_was_frozen)), mrb_bool_value(mrb_frozen_p((mrb_basic_ptr(path)))),
    mrb_symbol_value(MRB_SYM(block)),       block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_UNLINKAT);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_unlinkat(sqe, dfd, RSTRING_CSTR(mrb, path), (unsigned int) flags);
  mrb_obj_freeze(mrb, path);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_cancel(mrb_state *mrb, mrb_value self)
{
  mrb_value operation;
  mrb_int flags = IORING_ASYNC_CANCEL_ALL, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &operation, &flags, &sqe_flags, &block);
  mrb_data_check_type(mrb, operation, &mrb_io_uring_operation_type);


  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),       self,
    mrb_symbol_value(MRB_IVSYM(type)),       mrb_symbol_value(MRB_SYM(cancel)),
    mrb_symbol_value(MRB_IVSYM(operation)),  operation,
    mrb_symbol_value(MRB_SYM(block)),       block
  };
  mrb_value cancel_operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(cancel_operation), MRB_IORING_OP_CANCEL);
  mrb_data_init(cancel_operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_cancel(sqe, DATA_PTR(operation), (int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, cancel_operation, cancel_operation);

  return cancel_operation;
}

static mrb_value
mrb_io_uring_prep_cancel_fd(mrb_state *mrb, mrb_value self)
{
  mrb_value operation;
  mrb_int flags = IORING_ASYNC_CANCEL_FD, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "o|ii&", &operation, &flags, &sqe_flags, &block);
  mrb_data_check_type(mrb, operation, &mrb_io_uring_operation_type);


  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),       self,
    mrb_symbol_value(MRB_IVSYM(type)),       mrb_symbol_value(MRB_SYM(cancel)),
    mrb_symbol_value(MRB_IVSYM(operation)),  operation,
    mrb_symbol_value(MRB_SYM(block)),       block
  };
  mrb_value cancel_operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(cancel_operation), MRB_IORING_OP_CANCEL);
  mrb_data_init(cancel_operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_prep_cancel_fd(sqe, mrb_integer(mrb_type_convert(mrb, operation, MRB_TT_INTEGER, MRB_SYM(fileno))), (int) flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, cancel_operation, cancel_operation);

  return cancel_operation;
}

static mrb_value
mrb_io_uring_prep_statx(mrb_state *mrb, mrb_value self)
{
  mrb_value path = mrb_nil_value();
  mrb_value directory = mrb_nil_value();
  mrb_int flags = 0, mask = STATX_BASIC_STATS | STATX_BTIME, sqe_flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "S!|oiio&", &path, &directory, &flags, &mask, &sqe_flags, &block);
  const char *path_str = "";
  mrb_value path_was_frozen = mrb_false_value();
  if (mrb_nil_p(path)) {
    flags |= AT_EMPTY_PATH;
  } else {
    path_was_frozen = mrb_bool_value(mrb_frozen_p(mrb_basic_ptr(path)));
    path_str = RSTRING_CSTR(mrb, path);
    mrb_obj_freeze(mrb, path);
  }
  int dfd = AT_FDCWD;
  if(!mrb_nil_p(directory)) {
    dfd = mrb_integer(mrb_type_convert(mrb, directory, MRB_TT_INTEGER, MRB_SYM(fileno)));
  }

  struct statx *statxbuf = NULL;
  struct RData* statx_data = NULL;
  Data_Make_Struct(mrb, mrb_class_get_id(mrb, MRB_SYM(Statx)), struct statx, &mrb_io_uring_statx_type, statxbuf, statx_data);
  mrb_value statx = mrb_obj_value(statx_data);

  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);
  mrb_value argv[] = {
    mrb_symbol_value(MRB_IVSYM(ring)),          self,
    mrb_symbol_value(MRB_IVSYM(type)),          mrb_symbol_value(MRB_SYM(statx)),
    mrb_symbol_value(MRB_SYM(path)),            path,
    mrb_symbol_value(MRB_IVSYM(directory)),     directory,
    mrb_symbol_value(MRB_SYM(path_was_frozen)), path_was_frozen,
    mrb_symbol_value(MRB_SYM(statx)),         statx,
    mrb_symbol_value(MRB_SYM(block)),          block
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_io_uring->operation_class, NELEMS(argv), argv);
  uintptr_t encoded_operation = encode_operation_op(mrb, mrb_ptr(operation), MRB_IORING_OP_STATX);
  mrb_data_init(operation, (void *) encoded_operation, &mrb_io_uring_operation_type);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, (void *) encoded_operation);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  io_uring_prep_statx(sqe, dfd, path_str, flags, mask, statxbuf);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_int
mask_device(__u32 major, __u32 minor)
{
  return (major << 8) | minor;
}

static mrb_value
mrb_statx_set_instance_variables(mrb_state *mrb, mrb_value statx, struct statx *stx)
{
  mrb_iv_set(mrb, statx, MRB_IVSYM(mask), mrb_int_value(mrb, stx->stx_mask));
  mrb_iv_set(mrb, statx, MRB_IVSYM(blksize), mrb_int_value(mrb, stx->stx_blksize));
  mrb_iv_set(mrb, statx, MRB_IVSYM(attributes), mrb_int_value(mrb, stx->stx_attributes));

#ifdef STATX_NLINK
  if (stx->stx_mask & STATX_NLINK) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(nlink), mrb_int_value(mrb, stx->stx_nlink));
  }
#endif
#ifdef STATX_UID
  if (stx->stx_mask & STATX_UID) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(uid), mrb_int_value(mrb, stx->stx_uid));
  }
#endif
#ifdef STATX_GID
  if (stx->stx_mask & STATX_GID) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(gid), mrb_int_value(mrb, stx->stx_gid));
  }
#endif
#ifdef STATX_MODE
  if (stx->stx_mask & STATX_MODE) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(mode), mrb_int_value(mrb, stx->stx_mode));
  }
#endif
#ifdef STATX_INO
  if (stx->stx_mask & STATX_INO) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(ino), mrb_int_value(mrb, stx->stx_ino));
  }
#endif
#ifdef STATX_SIZE
  if (stx->stx_mask & STATX_SIZE) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(size), mrb_int_value(mrb, stx->stx_size));
  }
#endif
#ifdef STATX_BLOCKS
  if (stx->stx_mask & STATX_BLOCKS) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(blocks), mrb_int_value(mrb, stx->stx_blocks));
  }
#endif
  if (stx->stx_attributes_mask) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attributes_mask), mrb_int_value(mrb, stx->stx_attributes_mask));
  }

#ifdef STATX_ATTR_COMPRESSED
  if (stx->stx_attributes_mask & STATX_ATTR_COMPRESSED) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_compressed), mrb_bool_value(stx->stx_attributes & STATX_ATTR_COMPRESSED));
  }
#endif
#ifdef STATX_ATTR_IMMUTABLE
  if (stx->stx_attributes_mask & STATX_ATTR_IMMUTABLE) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_immutable), mrb_bool_value(stx->stx_attributes & STATX_ATTR_IMMUTABLE));
  }
#endif
#ifdef STATX_ATTR_APPEND
  if (stx->stx_attributes_mask & STATX_ATTR_APPEND) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_append), mrb_bool_value(stx->stx_attributes & STATX_ATTR_APPEND));
  }
#endif
#ifdef STATX_ATTR_NODUMP
  if (stx->stx_attributes_mask & STATX_ATTR_NODUMP) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_nodump), mrb_bool_value(stx->stx_attributes & STATX_ATTR_NODUMP));
  }
#endif
#ifdef STATX_ATTR_ENCRYPTED
  if (stx->stx_attributes_mask & STATX_ATTR_ENCRYPTED) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_encrypted), mrb_bool_value(stx->stx_attributes & STATX_ATTR_ENCRYPTED));
  }
#endif
#ifdef STATX_ATTR_AUTOMOUNT
  if (stx->stx_attributes_mask & STATX_ATTR_AUTOMOUNT) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_automount), mrb_bool_value(stx->stx_attributes & STATX_ATTR_AUTOMOUNT));
  }
#endif
#ifdef STATX_ATTR_MOUNT_ROOT
  if (stx->stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_mount_root), mrb_bool_value(stx->stx_attributes & STATX_ATTR_MOUNT_ROOT));
  }
#endif
#ifdef STATX_ATTR_VERITY
  if (stx->stx_attributes_mask & STATX_ATTR_VERITY) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_verity), mrb_bool_value(stx->stx_attributes & STATX_ATTR_VERITY));
  }
#endif
#ifdef STATX_ATTR_DAX
  if (stx->stx_attributes_mask & STATX_ATTR_DAX) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_dax), mrb_bool_value(stx->stx_attributes & STATX_ATTR_DAX));
  }
#endif
#ifdef STATX_ATTR_WRITE_ATOMIC
  if (stx->stx_attributes_mask & STATX_ATTR_WRITE_ATOMIC) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(attr_write_atomic), mrb_bool_value(stx->stx_attributes & STATX_ATTR_WRITE_ATOMIC));
  }
#endif

  mrb_value time_class = mrb_obj_value(mrb_class_get_id(mrb, MRB_SYM(Time)));
#ifdef STATX_ATIME
  if (stx->stx_mask & STATX_ATIME) {
    mrb_value atime = mrb_funcall_id(mrb, time_class, MRB_SYM(at), 2, mrb_int_value(mrb, stx->stx_atime.tv_sec), mrb_int_value(mrb, stx->stx_atime.tv_nsec / 1000));
    mrb_iv_set(mrb, statx, MRB_IVSYM(atime), atime);
  }
#endif
#ifdef STATX_BTIME
  if (stx->stx_mask & STATX_BTIME) {
    mrb_value btime = mrb_funcall_id(mrb, time_class, MRB_SYM(at), 2, mrb_int_value(mrb, stx->stx_btime.tv_sec), mrb_int_value(mrb, stx->stx_btime.tv_nsec / 1000));
    mrb_iv_set(mrb, statx, MRB_IVSYM(btime), btime);
  }
#endif
#ifdef STATX_CTIME
  if (stx->stx_mask & STATX_CTIME) {
    mrb_value ctime = mrb_funcall_id(mrb, time_class, MRB_SYM(at), 2, mrb_int_value(mrb, stx->stx_ctime.tv_sec), mrb_int_value(mrb, stx->stx_ctime.tv_nsec / 1000));
    mrb_iv_set(mrb, statx, MRB_IVSYM(ctime), ctime);
  }
#endif
#ifdef STATX_MTIME
  if (stx->stx_mask & STATX_MTIME) {
    mrb_value mtime = mrb_funcall_id(mrb, time_class, MRB_SYM(at), 2, mrb_int_value(mrb, stx->stx_mtime.tv_sec), mrb_int_value(mrb, stx->stx_mtime.tv_nsec / 1000));
    mrb_iv_set(mrb, statx, MRB_IVSYM(mtime), mtime);
  }
#endif

  if (stx->stx_rdev_major || stx->stx_rdev_minor) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(rdev), mrb_int_value(mrb, mask_device(stx->stx_rdev_major, stx->stx_rdev_minor)));
    mrb_iv_set(mrb, statx, MRB_IVSYM(rdev_major), mrb_int_value(mrb, stx->stx_rdev_major));
    mrb_iv_set(mrb, statx, MRB_IVSYM(rdev_minor), mrb_int_value(mrb, stx->stx_rdev_minor));
  }

  mrb_iv_set(mrb, statx, MRB_IVSYM(dev), mrb_int_value(mrb, mask_device(stx->stx_dev_major, stx->stx_dev_minor)));
  mrb_iv_set(mrb, statx, MRB_IVSYM(dev_major), mrb_int_value(mrb, stx->stx_dev_major));
  mrb_iv_set(mrb, statx, MRB_IVSYM(dev_minor), mrb_int_value(mrb, stx->stx_dev_minor));

#ifdef STATX_MNT_ID
  if (stx->stx_mask & STATX_MNT_ID) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(mnt_id), mrb_int_value(mrb, stx->stx_mnt_id));
  }
#endif
#ifdef STATX_DIOALIGN
  if (stx->stx_mask & STATX_DIOALIGN) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(dio_mem_align), mrb_int_value(mrb, stx->stx_dio_mem_align));
    mrb_iv_set(mrb, statx, MRB_IVSYM(dio_offset_align), mrb_int_value(mrb, stx->stx_dio_offset_align));
  }
#endif
#ifdef STATX_SUBVOL
  if (stx->stx_mask & STATX_SUBVOL) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(subvol), mrb_int_value(mrb, stx->stx_subvol));
  }
#endif
#ifdef STATX_WRITE_ATOMIC
  if (stx->stx_mask & STATX_WRITE_ATOMIC) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(atomic_write_unit_min), mrb_int_value(mrb, stx->stx_atomic_write_unit_min));
    mrb_iv_set(mrb, statx, MRB_IVSYM(atomic_write_unit_max), mrb_int_value(mrb, stx->stx_atomic_write_unit_max));
    mrb_iv_set(mrb, statx, MRB_IVSYM(atomic_write_segments_max), mrb_int_value(mrb, stx->stx_atomic_write_segments_max));
  }
#endif
#ifdef STATX_DIO_READ_ALIGN
  if (stx->stx_mask & STATX_DIO_READ_ALIGN) {
    mrb_iv_set(mrb, statx, MRB_IVSYM(dio_read_offset_align), mrb_int_value(mrb, stx->stx_dio_read_offset_align));
  }
#endif

  return statx;
}

static mrb_value
mrb_statx_initialize(mrb_state *mrb, mrb_value self)
{
  const char *path;
  mrb_value dirfd = mrb_nil_value();
  mrb_int flags = 0, mask = STATX_BASIC_STATS | STATX_BTIME;
  struct statx stx = {0};

  mrb_get_args(mrb, "z|oii", &path, &dirfd, &flags, &mask);
  int dfd = AT_FDCWD;
  if(!mrb_nil_p(dirfd)) {
    dfd = (int) mrb_integer(mrb_type_convert(mrb, dirfd, MRB_TT_INTEGER, MRB_SYM(fileno)));
  }

  if (syscall(SYS_statx, dfd, path, flags, mask, &stx) < 0) {
    mrb_sys_fail(mrb, "statx");
  }

  return mrb_statx_set_instance_variables(mrb, self, &stx);
}

static void
unset_if_not_frozen(mrb_state *mrb, mrb_value obj, const mrb_sym was_frozen_sym) {
    if (mrb_string_p(obj)) {
        mrb_value was_frozen = mrb_iv_get(mrb, obj, was_frozen_sym);
        if (!mrb_bool(was_frozen)) {
            MRB_UNSET_FROZEN_FLAG(mrb_basic_ptr(obj));
        }
    }
}

static mrb_value
mrb_io_uring_process_cqe(mrb_state *mrb, mrb_io_uring_t *mrb_io_uring, struct io_uring_cqe *cqe)
{
  uintptr_t userdata = (uintptr_t) io_uring_cqe_get_data(cqe);
  mrb_value operation = mrb_obj_value(decode_operation(userdata));
  mrb_value res = mrb_int_value(mrb, cqe->res);
  mrb_iv_set(mrb, operation, MRB_IVSYM(res), res);
  mrb_iv_set(mrb, operation, MRB_IVSYM(flags), mrb_int_value(mrb, cqe->flags));

  if (likely(cqe->res >= 0)) {
    switch(decode_op(userdata)) {
      case MRB_IORING_OP_READ_FIXED: {
        mrb_value index_val = mrb_iv_get(mrb, operation, MRB_SYM(buf_index));
        mrb_int index = mrb_as_int(mrb, index_val);
        mrb_value buf = mrb_ary_ref(mrb, mrb_io_uring->buffers, index);
        if (likely(mrb_string_p(buf))) {
          struct RString *buf_str = mrb_str_ptr(buf);
          RSTR_UNSET_SINGLE_BYTE_FLAG(buf_str);
          mrb_assert(cqe->res <= (RSTRING_CAPA(buf) + 1));
          RSTR_SET_LEN(buf_str, cqe->res);
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "buf not found");
        }
      } break;
      case MRB_IORING_OP_SOCKET:
      case MRB_IORING_OP_ACCEPT:
        mrb_iv_set(mrb, operation, MRB_IVSYM(sock), res);
        mrb_iv_set(mrb, operation, MRB_IVSYM(fileno), res);
      break;
      case MRB_IORING_OP_READ:
      case MRB_IORING_OP_RECV: {
        mrb_value index_val = mrb_iv_get(mrb, operation, MRB_SYM(buf_index));
        if (unlikely(mrb_integer_p(index_val))) {
          mrb_raise(mrb, E_FROZEN_ERROR, "can't modify frozen Buffer");
        }
        mrb_value buf = mrb_iv_get(mrb, operation, MRB_SYM(buf));
        if (likely(mrb_string_p(buf))) {
          MRB_UNSET_FROZEN_FLAG(mrb_basic_ptr((buf)));
          mrb_str_resize(mrb, buf, cqe->res);
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "buf is not a string");
        }
      } break;
      case MRB_IORING_OP_WRITE:
      case MRB_IORING_OP_SEND: {
        mrb_value buf = mrb_iv_get(mrb, operation, MRB_SYM(buf));
        unset_if_not_frozen(mrb, buf, MRB_SYM(buf_was_frozen));
      } break;
      case MRB_IORING_OP_UNLINKAT: {
        mrb_value path = mrb_iv_get(mrb, operation, MRB_SYM(path));
        unset_if_not_frozen(mrb, path, MRB_SYM(path_was_frozen));
      } break;
      case MRB_IORING_OP_OPENAT2: {
        mrb_iv_set(mrb, operation, MRB_IVSYM(file), res);
        mrb_iv_set(mrb, operation, MRB_IVSYM(fileno), res);
        mrb_value path = mrb_iv_get(mrb, operation, MRB_SYM(path));
        unset_if_not_frozen(mrb, path, MRB_SYM(path_was_frozen));
      } break;
      case MRB_IORING_OP_STATX: {
        mrb_value statx = mrb_iv_get(mrb, operation, MRB_SYM(statx));
        mrb_value path = mrb_iv_get(mrb, operation, MRB_SYM(path));
        unset_if_not_frozen(mrb, path, MRB_SYM(path_was_frozen));
        mrb_statx_set_instance_variables(mrb, statx, (struct statx *) DATA_PTR(statx));
      } break;
      default:
      break;
    }
  } else {
    mrb_value errno_val = mrb_int_value(mrb, -cqe->res);
    mrb_value exc = mrb_obj_new(mrb, mrb_class_get_id(mrb, MRB_SYM(SystemCallError)), 1, &errno_val);
    mrb_iv_set(mrb, operation, MRB_IVSYM(errno), exc);
  }
  return operation;
}

static mrb_value
mrb_io_uring_for_each_cqe(mrb_state* mrb, mrb_io_uring_t* mrb_io_uring, mrb_value block,
                          struct io_uring_cqe* cqe, int rc)
{
  unsigned int nr = 0;
  mrb_value operation = mrb_nil_value();

  try {
    unsigned head;
    int arena_index = mrb_gc_arena_save(mrb);
    const mrb_bool use_block = mrb_type(block) == MRB_TT_PROC;

    io_uring_for_each_cqe(&mrb_io_uring->ring, head, cqe) {
      nr++;

      operation = mrb_io_uring_process_cqe(mrb, mrb_io_uring, cqe);
      mrb_value prep_block = mrb_iv_get(mrb, operation, MRB_SYM(block));

      if (mrb_type(prep_block) == MRB_TT_PROC) {
        mrb_yield(mrb, prep_block, operation);
      }
      if (use_block) {
        mrb_yield(mrb, block, operation);
      }
      if (!(cqe->flags & IORING_CQE_F_MORE)) {
        mrb_hash_delete_key(mrb, mrb_io_uring->sqes, operation);
      }

      mrb_gc_arena_restore(mrb, arena_index);
    }

    io_uring_cq_advance(&mrb_io_uring->ring, nr);
  } catch (...) {
    io_uring_cq_advance(&mrb_io_uring->ring, nr);
      if (!(cqe->flags & IORING_CQE_F_MORE)) {
        mrb_hash_delete_key(mrb, mrb_io_uring->sqes, operation);
      }
    throw; // propagate the exception
  }

  return mrb_int_value(mrb, rc);
}


static mrb_value
mrb_io_uring_submit_and_wait_timeout(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = (mrb_io_uring_t *) DATA_PTR(self);

  mrb_int wait_nr = 1;
  mrb_float timeout = -1.0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "|if&", &wait_nr, &timeout, &block);

  struct io_uring_cqe *cqe = NULL;
  int rc;
  if (timeout > 0) {
    timeout += 1e-17; // we are adding this so ts can't become negative.
    struct __kernel_timespec ts = {
      .tv_sec  = (__kernel_time64_t) timeout,
      .tv_nsec = (long long)((timeout - (mrb_int)(timeout)) * NSEC_PER_SEC)
    };
    rc = io_uring_submit_and_wait_timeout(&mrb_io_uring->ring, &cqe, (unsigned int) wait_nr, &ts, NULL);
  } else {
    rc = io_uring_submit_and_wait_timeout(&mrb_io_uring->ring, &cqe, (unsigned int) wait_nr, NULL, NULL);
  }

  if (rc < 0) {
    errno = -rc;
    if (likely(errno == ETIME))
      return mrb_false_value();
    mrb_sys_fail(mrb, "io_uring_submit_and_wait_timeout");
  }

  return mrb_io_uring_for_each_cqe(mrb, mrb_io_uring, block, cqe, rc);
}

static __u64
mrb_io_uring_parse_flags_string(mrb_state *mrb, mrb_value flags_val)
{
  if (mrb_nil_p(flags_val)) {
    return 0;
  }
  const char *flags_str = RSTRING_CSTR(mrb, flags_val);

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

static __u64
mrb_io_uring_parse_resolve_string(mrb_state *mrb, mrb_value resolve)
{
  if (mrb_nil_p(resolve)) {
    return 0;
  }
  const char *resolve_str = RSTRING_CSTR(mrb, resolve);

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
  mrb_value flags_val = mrb_nil_value(), resolve = mrb_nil_value();
  mrb_int mode = -1;
  mrb_get_args(mrb, "|S!iS!", &flags_val, &mode, &resolve);

  struct open_how *how = (struct open_how *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*how));
  mrb_data_init(self, how, &mrb_io_uring_open_how_type);

  how->flags = mrb_io_uring_parse_flags_string(mrb, flags_val);
  if (mode == -1) {
    how->mode = mode = (how->flags & (O_CREAT | O_TMPFILE)) ? 0666 : 0;
  } else {
    how->mode = (unsigned long long) mode;
  }
  how->resolve = mrb_io_uring_parse_resolve_string(mrb, resolve);

  mrb_iv_set(mrb, self, MRB_IVSYM(flags),    flags_val);
  mrb_iv_set(mrb, self, MRB_IVSYM(mode),     mrb_int_value(mrb, mode));
  mrb_iv_set(mrb, self, MRB_IVSYM(resolve),  resolve);

  return self;
}

static mrb_value
mrb_io_uring_operation_class_init(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_int argc;
  mrb_get_args(mrb, "*", &argv, &argc);

  if (unlikely(argc < 6 || argc % 2 != 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "expecting an even number of arguments; and at least six");
  }

  for (mrb_int i = 0; i < argc;) {
    mrb_value arg_key = argv[i++];
    if (unlikely(!mrb_symbol_p(arg_key))) {
      mrb_raise(mrb, E_TYPE_ERROR, "expected symbol for key");
    }

    mrb_iv_set(mrb, self, mrb_symbol(arg_key), argv[i++]);
  }

  return self;
}

static mrb_value
mrb_io_uring_get_io_socket(mrb_state *mrb, struct RClass *base_class, mrb_int sockfd, unsigned int close_fd)
{
  struct RClass *socket_class = NULL;
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);

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
      socket_class = is_accept ? mrb_class_get_under_id(mrb, base_class, MRB_SYM(UNIXServer)) : mrb_class_get_under_id(mrb, base_class, MRB_SYM(UNIXSocket));
      break;
    case AF_INET:
    case AF_INET6:
      if (is_accept) {
        socket_class = mrb_class_get_under_id(mrb, base_class, MRB_SYM(TCPServer));
      } else {
        int socktype;
        if (unlikely(getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen) == -1)) {
          mrb_raise(mrb, E_RUNTIME_ERROR, "failed to get socket type");
        }
        switch (socktype) {
          case SOCK_STREAM:
            socket_class = mrb_class_get_under_id(mrb, base_class, MRB_SYM(TCPSocket));
            break;
          case SOCK_DGRAM:
            socket_class = mrb_class_get_under_id(mrb, base_class, MRB_SYM(UDPSocket));
            break;
          default: {
            socket_class = mrb_class_get_under_id(mrb, base_class, MRB_SYM(Socket));
          }
        }
      } break;
    default: {
      socket_class = mrb_class_get_under_id(mrb, base_class, MRB_SYM(Socket));
    }
  }

  mrb_value socket_obj = mrb_funcall_id(mrb, mrb_obj_value(socket_class), MRB_SYM(for_fd), 1, mrb_fixnum_value(sockfd));
  (void)mrb_io_fileno(mrb, socket_obj);
  ((struct mrb_io *)DATA_PTR(socket_obj))->close_fd = close_fd;
  return socket_obj;
}

static bool is_socket(int fd) {
    struct stat st;
    if (fstat(fd, &st) == -1) return false;
    return S_ISSOCK(st.st_mode);
}

static mrb_value
mrb_io_uring_operation_to_io(mrb_state *mrb, mrb_value self)
{
  mrb_value fdobj = mrb_iv_get(mrb, self, MRB_IVSYM(fileno));
  if (likely(!mrb_nil_p(fdobj))) {
    int fd = (int) mrb_integer(mrb_type_convert(mrb, fdobj, MRB_TT_INTEGER, MRB_SYM(fileno)));
    if (is_socket(fd)) {
      return mrb_io_uring_get_io_socket(mrb, mrb->object_class, fd, 0);
    } else {
      mrb_value file_obj = mrb_obj_new(mrb, mrb_class_get_id(mrb, MRB_SYM(File)), 1, &fdobj);
      (void)mrb_io_fileno(mrb, file_obj);
      ((struct mrb_io *)DATA_PTR(file_obj))->close_fd = 0;
      return file_obj;
    }
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "found no descriptor in operation to convert to IO");
    return mrb_undef_value();
  }
}

static mrb_value
mrb_io_uring_socket_for_fd(mrb_state *mrb, mrb_value self)
{
  mrb_value fdobj;
  mrb_get_args(mrb, "o", &fdobj);

  int sockfd = (int) mrb_integer(mrb_type_convert(mrb, fdobj, MRB_TT_INTEGER, MRB_SYM(fileno)));
  return mrb_io_uring_get_io_socket(mrb, mrb_class_ptr(self), sockfd, 1);
}

static mrb_value
mrb_io_uring_file_for_fd(mrb_state *mrb, mrb_value self)
{
  mrb_value fd;
  mrb_get_args(mrb, "o", &fd);


  mrb_value file_obj = mrb_obj_new(mrb, mrb_class_ptr(self), 1, &fd);
  (void)mrb_io_fileno(mrb, file_obj);
  ((struct mrb_io *)DATA_PTR(file_obj))->close_fd = 1;
  return file_obj;
}

static mrb_value
mrb_uring_readable(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, MRB_IVSYM(res));
  if (likely(mrb_integer_p(res)))
    return mrb_bool_value(mrb_integer(res) & POLLIN);
  return mrb_nil_value();
}

static mrb_value
mrb_uring_writable(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, MRB_IVSYM(res));
  if (likely(mrb_integer_p(res)))
    return mrb_bool_value(mrb_integer(res) & POLLOUT);
  return mrb_nil_value();
}

static mrb_value
mrb_io_uring_get_addrinfo(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(addrinfo));
}

static mrb_value
mrb_io_uring_get_buf(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(buf));
}

static mrb_value
mrb_io_uring_get_path(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(path));
}

static mrb_value
mrb_io_uring_get_open_how(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(open_how));
}

static mrb_value
mrb_io_uring_get_statx(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_SYM(statx));
}

static void
initialize_can_use_buffers_once()
{
  struct io_uring ring = {{0}};
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
    size_t ptr_bits = sizeof(uintptr_t) * 8;
    size_t op_bits = 8;

    // Create a mask for high bits where op would go
    uintptr_t high_mask = ((uintptr_t)0xFF) << (ptr_bits - op_bits);

    // If the address overlaps with the high bits, we can't use packing
    mrb_bool can_use_high_bits = !(address & high_mask);
    if (can_use_high_bits) {
        mrb_io_uring_operation_type.dfree = NULL;
        encode_operation_op = encode_operation_op_inline;
        decode_operation    = decode_operation_inline;
        decode_op           = decode_op_inline;
    } else {
        encode_operation_op = encode_operation_op_heap;
        decode_operation    = decode_operation_heap;
        decode_op           = decode_op_heap;
    }

    mrb_free(mrb, ptr);
  } else {
    pthread_mutex_unlock(&mutex);
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

MRB_BEGIN_DECL
void
mrb_mruby_io_uring_gem_init(mrb_state* mrb)
{
  pthread_mutex_lock(&mutex);
  if (init_once_done == FALSE) {
    init_once_done = TRUE;
    initialize_can_use_buffers_once();
    if (can_use_buffers) {
      page_size = sysconf(_SC_PAGESIZE);
      if (page_size <= 0) {
        pthread_mutex_unlock(&mutex);
        mrb_bug(mrb, "broken linux distro, returns a non positive page size");
      }
    }
    initialize_high_bits_check_once(mrb);
  }
  pthread_mutex_unlock(&mutex);

  struct RClass *io_uring_class, *io_uring_error_class, *io_uring_op_class, *io_uring_open_how_class;

  io_uring_class = mrb_define_class_under_id(mrb, mrb_class_get_id(mrb, MRB_SYM(IO)), MRB_SYM(Uring), mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method_id(mrb, io_uring_class, MRB_SYM(initialize),              mrb_io_uring_queue_init_params,       MRB_ARGS_OPT(2));
  mrb_define_method_id(mrb, io_uring_class, MRB_SYM(submit),                  mrb_io_uring_submit,                  MRB_ARGS_NONE());
  mrb_value op_types = mrb_ary_new(mrb);

  struct io_uring_probe *probe = io_uring_get_probe();
  if (!probe) {
    mrb_sys_fail(mrb, "io_uring_get_probe");
  }
  if (io_uring_opcode_supported(probe, IORING_OP_SOCKET)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_socket), mrb_io_uring_prep_socket, MRB_ARGS_ARG(2, 3)|MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(build_socket), mrb_io_uring_build_socket, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(socket)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_BIND)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_bind), mrb_io_uring_prep_bind, MRB_ARGS_ARG(2, 1)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(bind)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_LISTEN)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_listen), mrb_io_uring_prep_listen, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(listen)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_ACCEPT)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_accept), mrb_io_uring_prep_accept, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_multishot_accept), mrb_io_uring_prep_multishot_accept, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(accept)));
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(multishot_accept)));
    mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(SOCK_NONBLOCK), mrb_int_value(mrb, SOCK_NONBLOCK));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_CONNECT)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_connect), mrb_io_uring_prep_connect, MRB_ARGS_ARG(2, 1)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(connect)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_RECV)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_recv), mrb_io_uring_prep_recv, MRB_ARGS_ARG(1, 3)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(recv)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_SPLICE)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_splice), mrb_io_uring_prep_splice, MRB_ARGS_ARG(6, 1)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(splice)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_SEND)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_send), mrb_io_uring_prep_send, MRB_ARGS_ARG(2, 2)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(send)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_SHUTDOWN)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_shutdown), mrb_io_uring_prep_shutdown, MRB_ARGS_ARG(2, 1)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(shutdown)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_CLOSE)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_close), mrb_io_uring_prep_close, MRB_ARGS_ARG(1, 1)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(close)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_POLL_ADD)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_poll_add), mrb_io_uring_prep_poll_add, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_poll_multishot), mrb_io_uring_prep_poll_multishot, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_define_const_id (mrb, io_uring_class, MRB_SYM(POLL_ADD_MULTI),          mrb_int_value(mrb, IORING_POLL_ADD_MULTI));
    mrb_define_const_id (mrb, io_uring_class, MRB_SYM(POLL_UPDATE_EVENTS),      mrb_int_value(mrb, IORING_POLL_UPDATE_EVENTS));
    mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(POLLERR), mrb_int_value(mrb, POLLERR));
    mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(POLLHUP), mrb_int_value(mrb, POLLHUP));
    mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(POLLIN),  mrb_int_value(mrb, POLLIN));
    mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(POLLNVAL),mrb_int_value(mrb, POLLNVAL));
    mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(POLLOUT), mrb_int_value(mrb, POLLOUT));
    mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(POLLPRI), mrb_int_value(mrb, POLLPRI));
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(poll_add)));
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(poll_multishot)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_POLL_REMOVE)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_poll_update), mrb_io_uring_prep_poll_update, MRB_ARGS_ARG(3, 1)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(poll_update)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_OPENAT2)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_openat2), mrb_io_uring_prep_openat2, MRB_ARGS_ARG(1, 3)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(openat2)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_STATX)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_statx), mrb_io_uring_prep_statx, MRB_ARGS_ARG(1, 3)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(statx)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_READ)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_read), mrb_io_uring_prep_read, MRB_ARGS_ARG(1, 3)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(read)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_WRITE)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_write), mrb_io_uring_prep_write, MRB_ARGS_ARG(2, 2)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(write)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_UNLINKAT)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_unlinkat), mrb_io_uring_prep_unlinkat, MRB_ARGS_ARG(3, 1)|MRB_ARGS_BLOCK());
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(unlinkat)));
  }
  if (io_uring_opcode_supported(probe, IORING_OP_ASYNC_CANCEL)) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_cancel), mrb_io_uring_prep_cancel, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_cancel_fd), mrb_io_uring_prep_cancel_fd, MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_define_const_id (mrb, io_uring_class, MRB_SYM(ASYNC_CANCEL_ALL),        mrb_int_value(mrb, IORING_ASYNC_CANCEL_ALL));
    mrb_define_const_id (mrb, io_uring_class, MRB_SYM(ASYNC_CANCEL_FD),         mrb_int_value(mrb, IORING_ASYNC_CANCEL_FD));
    mrb_define_const_id (mrb, io_uring_class, MRB_SYM(ASYNC_CANCEL_ANY),        mrb_int_value(mrb, IORING_ASYNC_CANCEL_ANY));
    mrb_define_const_id (mrb, io_uring_class, MRB_SYM(ASYNC_CANCEL_FD_FIXED),   mrb_int_value(mrb, IORING_ASYNC_CANCEL_FD_FIXED));
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(cancel)));
    mrb_ary_push(mrb, op_types, mrb_symbol_value(MRB_SYM(cancel_fd)));
  }
  io_uring_free_probe(probe);
  mrb_obj_freeze(mrb, op_types);
  mrb_define_const_id(mrb, io_uring_class, MRB_SYM(OP_TYPES), op_types);
  if (can_use_buffers) {
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(fixed_buffer_size),       mrb_io_uring_get_fixed_buffer_size,   MRB_ARGS_NONE());
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_read_fixed),         mrb_io_uring_prep_read_fixed,         MRB_ARGS_ARG(1, 2)|MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(return_used_buffer),      mrb_io_uring_return_used_buffer_m,      MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, io_uring_class, MRB_SYM(prep_write_fixed), mrb_io_uring_prep_write_fixed, MRB_ARGS_ARG(2, 2)|MRB_ARGS_BLOCK());
  }
  mrb_define_method_id(mrb, io_uring_class,   MRB_SYM(wait),                     mrb_io_uring_submit_and_wait_timeout, MRB_ARGS_OPT(2)|MRB_ARGS_BLOCK());

  mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(SHUT_RD), mrb_int_value(mrb, SHUT_RD));
  mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(SHUT_WR), mrb_int_value(mrb, SHUT_WR));
  mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(SHUT_RDWR), mrb_int_value(mrb, SHUT_RDWR));
  mrb_define_const_id (mrb, mrb->kernel_module, MRB_SYM(AT_FDCWD), mrb_int_value(mrb, AT_FDCWD));

  io_uring_error_class = mrb_define_class_under_id(mrb, io_uring_class, MRB_SYM(Error), mrb->eStandardError_class);
  mrb_define_class_under_id(mrb, io_uring_class, MRB_SYM(SQRingFullError),  io_uring_error_class);

  io_uring_open_how_class = mrb_define_class_id(mrb, MRB_SYM(OpenHow), mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_open_how_class, MRB_TT_CDATA);
  mrb_define_method_id(mrb, io_uring_open_how_class, MRB_SYM(initialize), mrb_io_uring_open_how_init, MRB_ARGS_OPT(3));

  struct RClass *statx_class = mrb_define_class_id(mrb, MRB_SYM(Statx), mrb->object_class);
  MRB_SET_INSTANCE_TT(statx_class, MRB_TT_CDATA);
  mrb_define_method_id(mrb, statx_class, MRB_SYM(initialize), mrb_statx_initialize, MRB_ARGS_ARG(1, 3));

  /* Define constants for Statx */
#ifdef STATX_TYPE
  mrb_define_const_id(mrb, statx_class, MRB_SYM(TYPE), mrb_int_value(mrb, STATX_TYPE));
#endif
#ifdef STATX_MODE
  mrb_define_const_id(mrb, statx_class, MRB_SYM(MODE), mrb_int_value(mrb, STATX_MODE));
#endif
#ifdef STATX_NLINK
  mrb_define_const_id(mrb, statx_class, MRB_SYM(NLINK), mrb_int_value(mrb, STATX_NLINK));
#endif
#ifdef STATX_UID
  mrb_define_const_id(mrb, statx_class, MRB_SYM(UID), mrb_int_value(mrb, STATX_UID));
#endif
#ifdef STATX_GID
  mrb_define_const_id(mrb, statx_class, MRB_SYM(GID), mrb_int_value(mrb, STATX_GID));
#endif
#ifdef STATX_ATIME
  mrb_define_const_id(mrb, statx_class, MRB_SYM(ATIME), mrb_int_value(mrb, STATX_ATIME));
#endif
#ifdef STATX_MTIME
  mrb_define_const_id(mrb, statx_class, MRB_SYM(MTIME), mrb_int_value(mrb, STATX_MTIME));
#endif
#ifdef STATX_CTIME
  mrb_define_const_id(mrb, statx_class, MRB_SYM(CTIME), mrb_int_value(mrb, STATX_CTIME));
#endif
#ifdef STATX_INO
  mrb_define_const_id(mrb, statx_class, MRB_SYM(INO), mrb_int_value(mrb, STATX_INO));
#endif
#ifdef STATX_SIZE
  mrb_define_const_id(mrb, statx_class, MRB_SYM(SIZE), mrb_int_value(mrb, STATX_SIZE));
#endif
#ifdef STATX_BLOCKS
  mrb_define_const_id(mrb, statx_class, MRB_SYM(BLOCKS), mrb_int_value(mrb, STATX_BLOCKS));
#endif
#ifdef STATX_BASIC_STATS
  mrb_define_const_id(mrb, statx_class, MRB_SYM(BASIC_STATS), mrb_int_value(mrb, STATX_BASIC_STATS));
#endif
#ifdef STATX_BTIME
  mrb_define_const_id(mrb, statx_class, MRB_SYM(BTIME), mrb_int_value(mrb, STATX_BTIME));
#endif
#ifdef STATX_ALL
  mrb_define_const_id(mrb, statx_class, MRB_SYM(ALL), mrb_int_value(mrb, STATX_ALL));
#endif
#ifdef STATX_MNT_ID
  mrb_define_const_id(mrb, statx_class, MRB_SYM(MNT_ID), mrb_int_value(mrb, STATX_MNT_ID));
#endif
#ifdef STATX_DIOALIGN
  mrb_define_const_id(mrb, statx_class, MRB_SYM(DIOALIGN), mrb_int_value(mrb, STATX_DIOALIGN));
#endif
#ifdef STATX_WRITE_ATOMIC
  mrb_define_const_id(mrb, statx_class, MRB_SYM(WRITE_ATOMIC), mrb_int_value(mrb, STATX_WRITE_ATOMIC));
#endif
#ifdef STATX_SUBVOL
  mrb_define_const_id(mrb, statx_class, MRB_SYM(SUBVOL), mrb_int_value(mrb, STATX_SUBVOL));
#endif

  /* Define other constants in Kernel */
#ifdef AT_EMPTY_PATH
  mrb_define_const_id(mrb, mrb->kernel_module, MRB_SYM(AT_EMPTY_PATH), mrb_int_value(mrb, AT_EMPTY_PATH));
#endif
#ifdef AT_NO_AUTOMOUNT
  mrb_define_const_id(mrb, mrb->kernel_module, MRB_SYM(AT_NO_AUTOMOUNT), mrb_int_value(mrb, AT_NO_AUTOMOUNT));
#endif
#ifdef AT_SYMLINK_NOFOLLOW
  mrb_define_const_id(mrb, mrb->kernel_module, MRB_SYM(AT_SYMLINK_NOFOLLOW), mrb_int_value(mrb, AT_SYMLINK_NOFOLLOW));
#endif
#ifdef AT_STATX_SYNC_AS_STAT
  mrb_define_const_id(mrb, mrb->kernel_module, MRB_SYM(AT_STATX_SYNC_AS_STAT), mrb_int_value(mrb, AT_STATX_SYNC_AS_STAT));
#endif
#ifdef AT_STATX_FORCE_SYNC
  mrb_define_const_id(mrb, mrb->kernel_module, MRB_SYM(AT_STATX_FORCE_SYNC), mrb_int_value(mrb, AT_STATX_FORCE_SYNC));
#endif
#ifdef AT_STATX_DONT_SYNC
  mrb_define_const_id(mrb, mrb->kernel_module, MRB_SYM(AT_STATX_DONT_SYNC), mrb_int_value(mrb, AT_STATX_DONT_SYNC));
#endif
  mrb_define_const_id(mrb, mrb->kernel_module, MRB_SYM(SOMAXCONN), mrb_int_value(mrb, SOMAXCONN));


  io_uring_op_class = mrb_define_class_under_id(mrb, io_uring_class, MRB_SYM(Operation), mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_op_class, MRB_TT_CDATA);
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM(initialize),             mrb_io_uring_operation_class_init, MRB_ARGS_ANY());
  mrb_define_const_id (mrb, io_uring_op_class, MRB_SYM(CQE_F_BUFFER),         mrb_int_value(mrb, IORING_CQE_F_BUFFER));
  mrb_define_const_id (mrb, io_uring_op_class, MRB_SYM(CQE_F_MORE),           mrb_int_value(mrb, IORING_CQE_F_MORE));
  mrb_define_const_id (mrb, io_uring_op_class, MRB_SYM(CQE_F_SOCK_NONEMPTY),  mrb_int_value(mrb, IORING_CQE_F_SOCK_NONEMPTY));
  mrb_define_const_id (mrb, io_uring_op_class, MRB_SYM(CQE_F_NOTIF),          mrb_int_value(mrb, IORING_CQE_F_NOTIF));
  mrb_define_const_id (mrb, io_uring_op_class, MRB_SYM(SQE_IO_LINK),          mrb_int_value(mrb, IOSQE_IO_LINK));
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM(to_io),                  mrb_io_uring_operation_to_io, MRB_ARGS_KEY(1, 0));
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM_Q(readable),             mrb_uring_readable, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM_Q(writable),             mrb_uring_writable, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM(addrinfo),               mrb_io_uring_get_addrinfo,  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM(buf),                    mrb_io_uring_get_buf,  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM(path),                   mrb_io_uring_get_path,  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM(open_how),               mrb_io_uring_get_open_how,  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, io_uring_op_class, MRB_SYM(statx),                  mrb_io_uring_get_statx,  MRB_ARGS_NONE());

  struct RClass *io_uring_file_class = mrb_define_class_under_id(mrb, io_uring_class, MRB_SYM(File), mrb_class_get_id(mrb, MRB_SYM(File)));
  MRB_SET_INSTANCE_TT(io_uring_file_class, MRB_TT_CDATA);
  mrb_define_module_function_id(mrb, io_uring_file_class, MRB_SYM(for_fd), mrb_io_uring_file_for_fd, MRB_ARGS_REQ(2));
  struct RClass *io_uring_socket_class = mrb_define_class_under_id(mrb, io_uring_class, MRB_SYM(Socket), mrb_class_get_id(mrb, MRB_SYM(Socket)));
  MRB_SET_INSTANCE_TT(io_uring_socket_class, MRB_TT_CDATA);
  mrb_define_module_function_id(mrb, io_uring_socket_class, MRB_SYM(for_fd), mrb_io_uring_socket_for_fd, MRB_ARGS_REQ(2));
}

void mrb_mruby_io_uring_gem_final(mrb_state* mrb) {}
MRB_END_DECL