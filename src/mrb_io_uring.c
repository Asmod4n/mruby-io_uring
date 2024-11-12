#include "mrb_io_uring.h"

static mrb_value
mrb_io_uring_queue_init(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*ring));
  memset(ring, '\0', sizeof(*ring));
  mrb_data_init(self, ring, &mrb_io_uring_queue_type);

  mrb_int entries = 2048, flags = 0;
  mrb_get_args(mrb, "|iii", &entries, &flags);
  if (unlikely(entries <= 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too few entries");
  }

  int ret = io_uring_queue_init((unsigned int) entries, ring, (unsigned int) flags);
  if (likely(ret == 0)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sqes"), mrb_hash_new_capa(mrb, entries));
    mrb_value buffers = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_Buffers"), 1, &self);
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "buffers"), buffers);
    mrb_io_uring_buffers_t *buffers_t = DATA_PTR(buffers);
    ret = io_uring_register_buffers_sparse(ring, (unsigned int) buffers_t->max_buffers);
    if (likely(ret == 0)) {
      return self;
    } else {
      errno = -ret;
      mrb_sys_fail(mrb, "io_uring_register_buffers_sparse");   
    }
  } else {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_queue_init");
  }
}

static mrb_value
mrb_io_uring_buffers_init(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring;
  mrb_get_args(mrb, "d", &ring, &mrb_io_uring_queue_type);

  struct rlimit limit;
  if (unlikely(getrlimit(RLIMIT_MEMLOCK, &limit)) == -1) {
    mrb_sys_fail(mrb, "getrlimit");
  }
  limit.rlim_cur = limit.rlim_max;
  if (unlikely(setrlimit(RLIMIT_MEMLOCK, &limit)) == -1) {
    mrb_sys_fail(mrb, "setrlimit");
  }

  mrb_int max_buffers = limit.rlim_cur / MRB_IORING_BUFFER_SIZE;
  mrb_value buffers = mrb_hash_new_capa(mrb, max_buffers);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "buffers"), buffers);

  mrb_io_uring_buffers_t *buffers_t = (mrb_io_uring_buffers_t *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*buffers_t));
  memset(buffers_t, '\0', sizeof(*buffers_t));
  mrb_data_init(self, buffers_t, &mrb_io_uring_buffers_type);
  buffers_t->ring = ring;
  buffers_t->iovecs = (struct iovec *) mrb_calloc(mrb, max_buffers, sizeof(*buffers_t->iovecs));
  buffers_t->tags = (unsigned long long *) mrb_calloc(mrb, max_buffers, sizeof(*buffers_t->tags));
  buffers_t->free_list = mrb_ary_new(mrb);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "free_list"), buffers_t->free_list);
  buffers_t->allocated_buffers = 0;
  buffers_t->max_buffers = max_buffers;

  return self;
}

static mrb_value
mrb_io_uring_buffer_get(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_buffers_t *buffers_t = DATA_PTR(self);

  if (unlikely(!mrb_array_p(buffers_t->free_list))) {
    mrb_raise(mrb, E_TYPE_ERROR, "free_list is not an array");
  }

  if (RARRAY_LEN(buffers_t->free_list) > 0) {
    mrb_value index_val = mrb_ary_pop(mrb, buffers_t->free_list);
    mrb_int index = mrb_as_int(mrb, index_val);
    if (unlikely(index < 0 || index >= buffers_t->max_buffers)) mrb_raise(mrb, E_RANGE_ERROR, "index out of bounds");
    return mrb_assoc_new(mrb, index_val, mrb_obj_value((void *) buffers_t->tags[index]));
  }

  if (buffers_t->allocated_buffers < buffers_t->max_buffers) {
    mrb_value buffer = mrb_str_new_capa(mrb, MRB_IORING_BUFFER_SIZE);
    buffers_t->iovecs[buffers_t->allocated_buffers].iov_base = RSTRING_PTR(buffer);
    buffers_t->iovecs[buffers_t->allocated_buffers].iov_len = RSTRING_CAPA(buffer);
    buffers_t->tags[buffers_t->allocated_buffers] = (uintptr_t) mrb_cptr(buffer);
    int ret = io_uring_register_buffers_update_tag(buffers_t->ring, buffers_t->allocated_buffers, buffers_t->iovecs, buffers_t->tags, 1);
    if (likely(ret == 1)) {
      mrb_value index = mrb_int_value(mrb, buffers_t->allocated_buffers);
      mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "buffers")), buffer, index);
      buffers_t->allocated_buffers++;
      return mrb_assoc_new(mrb, index, buffer);
    } else {
      errno = -ret;
      mrb_sys_fail(mrb, "io_uring_register_buffers_update_tag");
    }
  }

  return mrb_nil_value();
}

static mrb_value
mrb_io_uring_buffer_return(mrb_state *mrb, mrb_value self)
{
  mrb_value buffer;
  mrb_get_args(mrb, "S", &buffer);

  mrb_io_uring_buffers_t *buffers_t = DATA_PTR(self);
  if (unlikely(!mrb_array_p(buffers_t->free_list))) {
    mrb_raise(mrb, E_TYPE_ERROR, "free_list is not an array");
  }
  mrb_value index = mrb_ensure_int_type(mrb, mrb_hash_get(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "buffers")), buffer));
  mrb_ary_push(mrb, buffers_t->free_list, index);
  MRB_UNSET_FROZEN_FLAG(mrb_obj_ptr(buffer));
  mrb_str_resize(mrb, buffer, MRB_IORING_BUFFER_SIZE);
  mrb_obj_freeze(mrb, buffer);

  return self;
}

static __u64
mrb_io_uring_parse_flags_string(mrb_state *mrb, const char *flags_str)
{
  if (!flags_str) {
    return 0;
  }
  __u64 flags = 0;
  mrb_bool seen_plus = FALSE;
  mrb_bool read_mode = FALSE;
  mrb_bool write_mode = FALSE;
  mrb_bool append_mode = FALSE;

  while (*flags_str) {
    if (*flags_str == '+') {
      if (seen_plus) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must be at the end with no characters following, and only once");
      }
      seen_plus = TRUE;
    } else if (seen_plus) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must be at the end with no characters following");
    }

    switch (*flags_str++) {
      case 'r':
        if (read_mode || write_mode || append_mode) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        read_mode = TRUE;
        flags |= O_RDONLY;
        break;
      case 'w':
        if (read_mode || write_mode || append_mode) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        write_mode = TRUE;
        flags |= O_WRONLY | O_CREAT | O_TRUNC;
        break;
      case 'a':
        if (read_mode || write_mode || append_mode) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        append_mode = TRUE;
        flags |= O_WRONLY | O_CREAT | O_APPEND;
        break;
      case '+':
        if (!(read_mode || write_mode || append_mode)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must follow 'r', 'w', or 'a'");
        }
        flags = (flags & ~O_ACCMODE) | O_RDWR;
        break;
      case 'e':
        if (flags & O_CLOEXEC) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'e' specified more than once");
        }
        flags |= O_CLOEXEC;
        break;
      case 's':
        if (flags & O_SYNC) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 's' specified more than once");
        }
        flags |= O_SYNC;
        break;
      case 'd':
        if (flags & O_DIRECT) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'd' specified more than once");
        }
        flags |= O_DIRECT;
        break;
      case 't':
        if (flags & O_TMPFILE) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 't' specified more than once");
        }
        flags |= O_TMPFILE;
        break;
      case 'n':
        switch (*flags_str++) {
          case 'a':
            if (flags & O_NOATIME) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'na' specified more than once");
            }
            flags |= O_NOATIME;
            break;
          case 'c':
            if (flags & O_NOCTTY) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'nc' specified more than once");
            }
            flags |= O_NOCTTY;
            break;
          case 'f':
            if (flags & O_NOFOLLOW) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'nf' specified more than once");
            }
            flags |= O_NOFOLLOW;
            break;
          case 'b':
            if (flags & O_NONBLOCK) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'nb' specified more than once");
            }
            flags |= O_NONBLOCK;
            break;
          default:
            mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid flags string");
        }
        break;
      case 'D':
        if (flags & O_DIRECTORY) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'D' specified more than once");
        }
        flags |= O_DIRECTORY;
        break;
      case 'P':
        if (flags & O_PATH) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'P' specified more than once");
        }
        flags |= O_PATH;
        break;
      case 'l':
        if (flags & O_LARGEFILE) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'l' specified more than once");
        }
        flags |= O_LARGEFILE;
        break;
      default:
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid flags string");
    }
  }

  // Final validation:
  if (((flags & O_WRONLY) && (flags & O_RDWR)) || !(flags & (O_RDONLY | O_WRONLY | O_RDWR))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
  }

  return flags;
}

static __u64
mrb_io_uring_parse_resolve_string(mrb_state *mrb, const char *resolve_str)
{
  if (!resolve_str) {
    return 0;
  }
  __u64 resolve_flags = 0;

  while (*resolve_str) {
    switch (*resolve_str++) {
      case 'L':
        if (resolve_flags & RESOLVE_NO_SYMLINKS) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'L' specified more than once");
        }
        resolve_flags |= RESOLVE_NO_SYMLINKS;
        break;
      case 'X':
        if (resolve_flags & RESOLVE_NO_XDEV) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'X' specified more than once");
        }
        resolve_flags |= RESOLVE_NO_XDEV;
        break;
      case 'C':
        if (resolve_flags & RESOLVE_CACHED) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'C' specified more than once");
        }
        resolve_flags |= RESOLVE_CACHED;
        break;
      case 'B':
        if (resolve_flags & RESOLVE_BENEATH) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'B' specified more than once");
        }
        resolve_flags |= RESOLVE_BENEATH;
        break;
      case 'R':
        if (resolve_flags & RESOLVE_IN_ROOT) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'R' specified more than once");
        }
        resolve_flags |= RESOLVE_IN_ROOT;
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
  struct open_how *how = mrb_realloc(mrb, DATA_PTR(self), sizeof(*how));
  mrb_data_init(self, how, &mrb_io_uring_open_how_type);
  const char *flags = NULL;
  mrb_int mode = 0;
  const char *resolve = NULL;
  mrb_get_args(mrb, "|z!iz!", &flags, &mode, &resolve);

  how->flags = mrb_io_uring_parse_flags_string(mrb, flags);
  how->mode = mode;
  how->resolve = mrb_io_uring_parse_resolve_string(mrb, resolve);

  return self;
}

static struct io_uring_sqe *
mrb_io_uring_get_sqe(mrb_state *mrb, mrb_value self)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(DATA_PTR(self));
  if (unlikely(!sqe)) {
    mrb_raise(mrb, E_IO_URING_SQ_RING_FULL_ERROR, "SQ ring is currently full and entries must be submitted for processing before new ones can get allocated");
  }
  return sqe;
}

static mrb_value
mrb_io_uring_submit(mrb_state *mrb, mrb_value self)
{
  int ret = io_uring_submit(DATA_PTR(self));
  if (unlikely(ret < 0)) {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_submit");
  }

  return mrb_int_value(mrb, ret);
}

static mrb_value
mrb_io_uring_prep_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int domain, type, protocol, flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "iii|ii", &domain, &type, &protocol, &flags, &sqe_flags);

  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_SocketOp"), 1, &self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_socket(sqe, (int) domain, (int) type, (int) protocol, (unsigned int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &flags, &sqe_flags);

  mrb_value argv[] = { self, sock };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_AcceptOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));

  io_uring_prep_accept(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  NULL, NULL,
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_multishot_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &flags, &sqe_flags);

  mrb_value argv[] = { self, sock };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_MultishotAcceptOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));

  io_uring_prep_multishot_accept(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  NULL, NULL,
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_recv(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int len = 0, flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|iii", &sock, &len, &flags, &sqe_flags);
  int socket = (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno"));
  if (len <= 0) {
    socklen_t optlen = sizeof(len);
    if (unlikely(getsockopt(socket, SOL_SOCKET, SO_RCVBUF, &len, &optlen) != 0)) {
      mrb_sys_fail(mrb, "getsockopt");
    }
  }

  mrb_value buf = mrb_str_new_capa(mrb, len);
  mrb_obj_freeze(mrb, buf);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  mrb_value argv[] = { self, sock, buf };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_RecvOp"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));

  io_uring_prep_recv(sqe,
  socket,
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_splice(mrb_state *mrb, mrb_value self)
{
  mrb_value fd_in, fd_out;
  mrb_int off_in, off_out, nbytes, splice_flags, sqe_flags = 0;
  mrb_get_args(mrb, "oioiii|i", &fd_in, &off_in, &fd_out, &off_out, &nbytes, &splice_flags, &sqe_flags);

  mrb_value argv[] = { self, fd_in, fd_out };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_SpliceOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));

  io_uring_prep_splice(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, fd_in,  MRB_TT_INTEGER, "Integer", "fileno")), off_in,
  (int) mrb_integer(mrb_convert_type(mrb, fd_out, MRB_TT_INTEGER, "Integer", "fileno")), off_out,
  (unsigned int) nbytes, (unsigned int) splice_flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_send(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "oS|ii", &sock, &buf, &flags, &sqe_flags);

  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = { self, sock, buf };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_SendOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));

  io_uring_prep_send(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int how, sqe_flags = 0;
  mrb_get_args(mrb, "oi|i", &sock, &how, &sqe_flags);

  mrb_value argv[] = { self, sock };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_ShutdownOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_shutdown(sqe, (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")), (int) how);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_close(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int sqe_flags = 0;
  mrb_get_args(mrb, "o|i", &sock, &sqe_flags);

  mrb_value argv[] = { self, sock };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_CloseOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_close(sqe, (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")));
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_add(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &poll_mask, &sqe_flags);

  mrb_value argv[] = { self, sock, mrb_int_value(mrb, poll_mask) };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_PollAddOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_poll_add(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (unsigned int) poll_mask);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_multishot(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &poll_mask, &sqe_flags);

  mrb_value argv[] = { self, sock, mrb_int_value(mrb, poll_mask) };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_PollMultishotOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_poll_multishot(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (unsigned int) poll_mask);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

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

  mrb_value argv[] = { self, old_operation, mrb_int_value(mrb, poll_mask) };
  mrb_value new_operation;
  new_operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_PollUpdateOp"), NELEMS(argv), argv);
  mrb_value sqes = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes"));
  mrb_hash_set(mrb, sqes, new_operation, new_operation);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(new_operation));
  io_uring_prep_poll_update(sqe,
  (uintptr_t) mrb_ptr(old_operation), (uintptr_t) mrb_ptr(new_operation),
  (unsigned int) poll_mask, (unsigned int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_delete_key(mrb, sqes, old_operation);

  return new_operation;
}

static mrb_value
mrb_io_uring_prep_openat2(mrb_state *mrb, mrb_value self)
{
  mrb_value path_str, directory_fileno = mrb_nil_value(), open_how = mrb_nil_value();
  mrb_int sqe_flags = 0;
  mrb_get_args(mrb, "S|ooi", &path_str, &directory_fileno, &open_how, &sqe_flags);
  int dfd = AT_FDCWD;
  if (!mrb_nil_p(directory_fileno)) {
    dfd = (int) mrb_integer(mrb_convert_type(mrb, directory_fileno, MRB_TT_INTEGER, "Integer", "fileno"));
  }
  struct open_how *how = NULL;
  if (mrb_nil_p(open_how)) {
    open_how = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "OpenHow"), 0, NULL);
  }
  how = mrb_data_get_ptr(mrb, open_how, &mrb_io_uring_open_how_type);

  mrb_value argv[] = { self, path_str, directory_fileno, open_how };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_OpenAt2Op"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_openat2(sqe, dfd, mrb_string_value_cstr(mrb, &path_str), how);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_read(mrb_state *mrb, mrb_value self)
{
  mrb_value fileno;
  mrb_int nbytes = 4096, offset = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|iii", &fileno, &nbytes, &offset, &sqe_flags);
  
  mrb_value buf = mrb_str_new_capa(mrb, nbytes);
  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = { self, fileno, buf };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_ReadOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_read(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, fileno, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (unsigned long long) offset);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_read_fixed(mrb_state *mrb, mrb_value ring)
{
  mrb_value fileno;
  mrb_int offset = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &fileno, &offset, &sqe_flags);
  int fd = (int) mrb_integer(mrb_convert_type(mrb, fileno, MRB_TT_INTEGER, "Integer", "fileno"));

  mrb_value buffers = mrb_iv_get(mrb, ring, mrb_intern_lit(mrb, "buffers"));
  mrb_value buffer = mrb_io_uring_buffer_get(mrb, buffers);
  if (unlikely(mrb_nil_p(buffer))) {
    mrb_raise(mrb, E_IO_URING_NO_BUFFERS_ERROR, "All fixed buffers are in use, you have to return them with ring.buffer_return(operation.buf) after you are done using them.");
  }
  mrb_io_uring_buffers_t *buffers_t = DATA_PTR(buffers);
  mrb_int index = mrb_as_int(mrb, mrb_ary_ref(mrb, buffer, 0));
  if (unlikely(index < 0 || index >= buffers_t->max_buffers)) mrb_raise(mrb, E_RANGE_ERROR, "index out of bounds");
  mrb_value buf = mrb_ary_ref(mrb, buffer, 1);
  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = { ring, fileno, buf };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, ring), "_ReadFixedOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_read_fixed(sqe,
  fd,
  buffers_t->iovecs[index].iov_base, RSTRING_CAPA(buf),
  (unsigned long long) offset, index);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, ring, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_write(mrb_state *mrb, mrb_value self)
{
  mrb_value fileno, buf;
  mrb_int offset, sqe_flags = 0;
  mrb_get_args(mrb, "oSi|i", &fileno, &buf, &offset, &sqe_flags);

  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = { self, fileno, buf };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_WriteOp"), NELEMS(argv), argv);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));

  io_uring_prep_write(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, fileno, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (__u64) offset);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_cancel(mrb_state *mrb, mrb_value self)
{
  mrb_value operation;
  mrb_int flags = IORING_ASYNC_CANCEL_ALL, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &operation, &flags, &sqe_flags);
  mrb_data_check_type(mrb, operation, &mrb_io_uring_operation_type);

  mrb_value argv[] = { self, operation };
  mrb_value cancel_operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_CancelOp"), NELEMS(argv), argv);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), cancel_operation, cancel_operation);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, self);
  io_uring_sqe_set_data(sqe, mrb_ptr(cancel_operation));
  io_uring_prep_cancel(sqe, mrb_ptr(operation), (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  return cancel_operation;
}

static mrb_value
mrb_io_uring_socket_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val;
  mrb_get_args(mrb, "o", &ring_val);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = SOCKET;
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "socket")));

  return self;
}

static mrb_value
mrb_io_uring_socket_operation_to_tcpserver(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  mrb_value tcp_server = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "TCPServer")), "for_fd", 1, res);
  (void) mrb_io_fileno(mrb, tcp_server);
  ((struct mrb_io *)DATA_PTR(tcp_server))->close_fd = 0;
  return tcp_server;
}

static mrb_value
mrb_io_uring_socket_operation_to_udpsocket(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  mrb_value udp_socket = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "UDPSocket")), "for_fd", 1, res);
  (void) mrb_io_fileno(mrb, udp_socket);
  ((struct mrb_io *)DATA_PTR(udp_socket))->close_fd = 0;
  return udp_socket;
}

static mrb_value
mrb_io_uring_socket_operation_to_socket(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  mrb_value sock = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "Socket")), "for_fd", 1, res);
  (void) mrb_io_fileno(mrb, sock);
  ((struct mrb_io *)DATA_PTR(sock))->close_fd = 0;
  return sock;
}

static mrb_value
mrb_io_uring_socket_operation_to_unixserver(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  mrb_value unix_server = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "UNIXServer")), "for_fd", 1, res);
  (void) mrb_io_fileno(mrb, unix_server);
  ((struct mrb_io *)DATA_PTR(unix_server))->close_fd = 0;
  return unix_server;
}

static mrb_value
mrb_io_uring_accept_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = ACCEPT;
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "accept")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
mrb_io_uring_multishot_accept_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = MULTISHOTACCEPT;
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "multishot_accept")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
mrb_io_uring_operation_to_tcpsocket(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  mrb_value tcp_socket = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "TCPSocket")), "for_fd", 1, res);
  (void) mrb_io_fileno(mrb, tcp_socket);
  ((struct mrb_io *)DATA_PTR(tcp_socket))->close_fd = 0;
  return tcp_socket;
}

static mrb_value
mrb_io_uring_operation_to_unixsocket(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  mrb_value unix_socket = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "UNIXSocket")), "for_fd", 1, res);
  (void) mrb_io_fileno(mrb, unix_socket);
  ((struct mrb_io *)DATA_PTR(unix_socket))->close_fd = 0;
  return unix_socket;
}

static mrb_value
mrb_io_uring_recv_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock, buf;
  mrb_get_args(mrb, "ooo", &ring_val, &sock, &buf);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = RECV;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "recv")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@buf"),  buf);

  return self;
}

static mrb_value
mrb_io_uring_splice_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, fd_in, fd_out;
  mrb_get_args(mrb, "ooo", &ring_val, &fd_in, &fd_out);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = SPLICE;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "splice")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), mrb_assoc_new(mrb, fd_in, fd_out));

  return self;
}

static mrb_value
mrb_io_uring_send_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock, buf;
  mrb_get_args(mrb, "ooo", &ring_val, &sock, &buf);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = SEND;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "send")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@buf"),  buf);

  return self;
}

static mrb_value
mrb_io_uring_shutdown_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = SHUTDOWN;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "shutdown")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
mrb_io_uring_close_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = CLOSE;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "close")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
mrb_io_uring_poll_add_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock, poll_mask;
  mrb_get_args(mrb, "ooo", &ring_val, &sock, &poll_mask);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = POLLADD;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "poll_add")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@poll_mask"), poll_mask);

  return self;
}

static mrb_value
mrb_io_uring_poll_multishot_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock, poll_mask;
  mrb_get_args(mrb, "ooo", &ring_val, &sock, &poll_mask);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = POLLMULTISHOT;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "poll_multishot")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@poll_mask"), poll_mask);

  return self;
}

static mrb_value
mrb_io_uring_poll_update_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, old_operation, poll_mask;
  mrb_get_args(mrb, "ooo", &ring_val, &old_operation, &poll_mask);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = POLLUPDATE;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"),       mrb_symbol_value(mrb_intern_lit(mrb, "poll_update")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"),       mrb_iv_get(mrb, old_operation, mrb_intern_lit(mrb, "@sock")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@poll_mask"),  poll_mask);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@userdata"),   mrb_iv_get(mrb, old_operation, mrb_intern_lit(mrb, "@userdata")));

  return self;
}

static mrb_value
mrb_io_uring_openat2_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, path_str, directory_fileno, open_how;
  mrb_get_args(mrb, "oooo", &ring_val, &path_str, &directory_fileno, &open_how);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation_p = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation_p));
  mrb_data_init(self, operation_p, &mrb_io_uring_operation_type);
  *operation_p = OPENAT2;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "openat2")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@path"), path_str);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@directory_fileno"), directory_fileno);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@open_how"), open_how);

  return self;
}

static mrb_value
mrb_io_uring_openat2_to_file(mrb_state *mrb, mrb_value self)
{
  mrb_value res = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@res"));
  mrb_value file = mrb_obj_new(mrb, mrb_class_get(mrb, "File"), 1, &res);
  (void) mrb_io_fileno(mrb, file);
  ((struct mrb_io *)DATA_PTR(file))->close_fd = 0;
  return file;
}

static mrb_value
mrb_io_uring_read_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, fileno, buf;
  mrb_get_args(mrb, "ooo", &ring_val, &fileno, &buf);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation_p = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation_p));
  mrb_data_init(self, operation_p, &mrb_io_uring_operation_type);
  *operation_p = READ;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "read")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@fileno"), fileno);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@buf"), buf);

  return self;
}

static mrb_value
mrb_io_uring_read_fixed_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, fileno, buf;
  mrb_get_args(mrb, "ooo", &ring_val, &fileno, &buf);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation_p = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation_p));
  mrb_data_init(self, operation_p, &mrb_io_uring_operation_type);
  *operation_p = READFIXED;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "read_fixed")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@fileno"), fileno);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@buf"), buf);

  return self;
}

static mrb_value
mrb_io_uring_write_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, fileno, buf;
  mrb_get_args(mrb, "ooo", &ring_val, &fileno, &buf);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation));
  mrb_data_init(self, operation, &mrb_io_uring_operation_type);
  *operation = WRITE;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "write")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@fileno"), fileno);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@buf"),  buf);

  return self;
}

static mrb_value
mrb_io_uring_cancel_operation_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, operation;
  mrb_get_args(mrb, "oo", &ring_val, &operation);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@ring"), ring_val);

  enum mrb_io_uring_op_types *operation_p = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation_p));
  mrb_data_init(self, operation_p, &mrb_io_uring_operation_type);
  *operation_p = CANCEL;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "cancel")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@operation"), operation);

  return self;
}

static mrb_value
mrb_io_uring_process_cqe(mrb_state *mrb, struct io_uring_cqe *cqe)
{
  mrb_value operation = mrb_obj_value(io_uring_cqe_get_data(cqe));
  mrb_data_check_type(mrb, operation, &mrb_io_uring_operation_type);
  mrb_value res = mrb_int_value(mrb, cqe->res);
  mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@res"), res);
  mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@flags"), mrb_int_value(mrb, cqe->flags));
  enum mrb_io_uring_op_types *operation_t = DATA_PTR(operation);

  if (likely(cqe->res >= 0)) {
    switch(*operation_t) {
      case SOCKET:
        mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@sock"), res);
      break;
      case OPENAT2:
        mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@fileno"), res);
      break;
      case RECV:
      case READ:
      case READFIXED: {
        mrb_value buf = mrb_iv_get(mrb, operation, mrb_intern_lit(mrb, "@buf"));
        if (likely(mrb_string_p(buf))) {
          MRB_UNSET_FROZEN_FLAG(mrb_obj_ptr(buf));
          mrb_str_resize(mrb, buf, cqe->res);
          if (*operation_t == READFIXED) mrb_obj_freeze(mrb, buf);
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "buf is not a string");
        }
      } break;
      case SEND:
      case WRITE: {
        mrb_value buf = mrb_iv_get(mrb, operation, mrb_intern_lit(mrb, "@buf"));
        if (likely(mrb_string_p(buf))) {
          MRB_UNSET_FROZEN_FLAG(mrb_obj_ptr(buf));
        } else {
          mrb_raise(mrb, E_TYPE_ERROR, "buf is not a string");
        }
      } break;
      default:
      break;
    }   
  } else {
    mrb_value errno_val = mrb_fixnum_value(-cqe->res);
    mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@errno"), mrb_obj_new(mrb, mrb_class_get(mrb, "SystemCallError"), 1, &errno_val));
  }

  return operation;
}

static mrb_value
mrb_io_uring_iterate_over_cqes(mrb_state *mrb, mrb_value self, struct io_uring *ring, mrb_value block, struct io_uring_cqe *cqe)
{
  mrb_value sqes = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes"));
  unsigned head;
  unsigned int i = 0;

  if (mrb_type(block) == MRB_TT_PROC) {
    struct mrb_jmpbuf* prev_jmp = mrb->jmp;
    struct mrb_jmpbuf c_jmp;
    int arena_index = mrb_gc_arena_save(mrb);
    MRB_TRY(&c_jmp)
    {
      mrb->jmp = &c_jmp;
      io_uring_for_each_cqe(ring, head, cqe) {
        mrb_value operation = mrb_io_uring_process_cqe(mrb, cqe);
        mrb_yield(mrb, block, operation);
        if (!(cqe->flags & IORING_CQE_F_MORE)) {
          mrb_hash_delete_key(mrb, sqes, operation);
        }
        mrb_gc_arena_restore(mrb, arena_index);
        i++;
      }
      io_uring_cq_advance(ring, i);
      mrb->jmp = prev_jmp;
    }
    MRB_CATCH(&c_jmp)
    {
      mrb->jmp = prev_jmp;
      io_uring_cq_advance(ring, i);
      MRB_THROW(mrb->jmp);
    }
    MRB_END_EXC(&c_jmp);

    return self;
  } else {
    mrb_value operations = mrb_ary_new_capa(mrb, mrb_hash_size(mrb, sqes));
    int arena_index = mrb_gc_arena_save(mrb);
    io_uring_for_each_cqe(ring, head, cqe) {
      mrb_value operation = mrb_io_uring_process_cqe(mrb, cqe);
      mrb_ary_push(mrb, operations, operation);
      if (!(cqe->flags & IORING_CQE_F_MORE)) {
        mrb_hash_delete_key(mrb, sqes, operation);
      }
      mrb_gc_arena_restore(mrb, arena_index);
      i++;
    }
    io_uring_cq_advance(ring, i);

    return operations;
  }
}

static mrb_value
mrb_io_uring_wait_cqe_timeout(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) DATA_PTR(self);
  int rc = io_uring_submit(ring);
  if (unlikely(rc < 0)) {
    errno = -rc;
    mrb_sys_fail(mrb, "io_uring_submit");
  }

  mrb_float timeout = -1.0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "|f&", &timeout, &block);

  struct io_uring_cqe *cqe = NULL;
  if (timeout >= 0.0) {
    timeout += 0.5e-9; // we are adding this so ts can't become negative.
    struct __kernel_timespec ts = {
      .tv_sec  = timeout,
      .tv_nsec = (timeout - (mrb_int)(timeout)) * NSEC_PER_SEC
    };
    rc = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
  } else {
    rc = io_uring_wait_cqe_timeout(ring, &cqe, NULL);
  }

  if (rc < 0) {
    errno = -rc;
    if (likely(errno == ETIME))
      return mrb_false_value();
    mrb_sys_fail(mrb, "io_uring_wait_cqe_timeout");
  }

  return mrb_io_uring_iterate_over_cqes(mrb, self, ring, block, cqe);
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

void
mrb_mruby_io_uring_gem_init(mrb_state* mrb)
{
  struct RClass *io_uring_class, *io_uring_buffers_class,
  *io_uring_error_class, *io_uring_op_class, *io_uring_socket_operation_class,
  *io_uring_accept_operation_class, *io_uring_multishot_accept_operation_class,
  *io_uring_recv_operation_class, *io_uring_splice_operation_class,
  *io_uring_send_operation_class, *io_uring_shutdown_operation_class,
  *io_uring_close_operation_class, *io_uring_poll_add_operation_class,
  *io_uring_poll_multishot_operation_class, *io_uring_poll_update_operation_class,
  *io_uring_read_operation_class, *io_uring_read_fixed_operation_class,
  *io_uring_cancel_operation_class, *io_uring_open_how_class, *io_uring_openat2_operation_class,
  *io_uring_write_operation_class;

  io_uring_class = mrb_define_class_under(mrb, mrb_class_get(mrb, "IO"), "Uring", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_class, "initialize",              mrb_io_uring_queue_init,              MRB_ARGS_OPT(2));
  mrb_define_method(mrb, io_uring_class, "submit",                  mrb_io_uring_submit,                  MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_class, "prep_socket",  	          mrb_io_uring_prep_socket,             MRB_ARGS_ARG(3, 2));
  mrb_define_method(mrb, io_uring_class, "prep_accept",  	          mrb_io_uring_prep_accept,             MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "prep_multishot_accept",  	mrb_io_uring_prep_multishot_accept,   MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "prep_recv",  	            mrb_io_uring_prep_recv,               MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, io_uring_class, "prep_splice",  	          mrb_io_uring_prep_splice,             MRB_ARGS_ARG(6, 1));
  mrb_define_method(mrb, io_uring_class, "prep_send",  	            mrb_io_uring_prep_send,               MRB_ARGS_ARG(2, 2));
  mrb_define_method(mrb, io_uring_class, "prep_shutdown",           mrb_io_uring_prep_shutdown,           MRB_ARGS_ARG(2, 1));
  mrb_define_method(mrb, io_uring_class, "prep_close",              mrb_io_uring_prep_close,              MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, io_uring_class, "prep_poll_add",           mrb_io_uring_prep_poll_add,           MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "prep_poll_multishot",     mrb_io_uring_prep_poll_multishot,     MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "prep_poll_update",        mrb_io_uring_prep_poll_update,        MRB_ARGS_ARG(3, 1));
  mrb_define_method(mrb, io_uring_class, "prep_openat2",            mrb_io_uring_prep_openat2,            MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, io_uring_class, "prep_read",               mrb_io_uring_prep_read,               MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, io_uring_class, "prep_read_fixed",         mrb_io_uring_prep_read_fixed,         MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "prep_write",  	          mrb_io_uring_prep_write,              MRB_ARGS_ARG(3, 1));
  mrb_define_method(mrb, io_uring_class, "prep_cancel",  	          mrb_io_uring_prep_cancel,             MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "wait",  	                mrb_io_uring_wait_cqe_timeout,        MRB_ARGS_OPT(1));
  mrb_define_method(mrb, io_uring_class, "buffer_return",  	        mrb_io_uring_buffer_return,           MRB_ARGS_REQ(1));
  mrb_define_const (mrb, io_uring_class, "ASYNC_CANCEL_ALL",        mrb_fixnum_value(IORING_ASYNC_CANCEL_ALL));
  mrb_define_const (mrb, io_uring_class, "ASYNC_CANCEL_FD",         mrb_fixnum_value(IORING_ASYNC_CANCEL_FD));
  mrb_define_const (mrb, io_uring_class, "ASYNC_CANCEL_ANY",        mrb_fixnum_value(IORING_ASYNC_CANCEL_ANY));
  mrb_define_const (mrb, io_uring_class, "ASYNC_CANCEL_FD_FIXED",   mrb_fixnum_value(IORING_ASYNC_CANCEL_FD_FIXED));
  mrb_define_const (mrb, io_uring_class, "POLL_ADD_MULTI",          mrb_fixnum_value(IORING_POLL_ADD_MULTI));
  mrb_define_const (mrb, io_uring_class, "POLL_UPDATE_EVENTS",      mrb_fixnum_value(IORING_POLL_UPDATE_EVENTS));
  mrb_define_const (mrb, io_uring_class, "POLLERR", mrb_fixnum_value(POLLERR));
  mrb_define_const (mrb, io_uring_class, "POLLHUP", mrb_fixnum_value(POLLHUP));
  mrb_define_const (mrb, io_uring_class, "POLLIN",  mrb_fixnum_value(POLLIN));
  mrb_define_const (mrb, io_uring_class, "POLLNVAL",mrb_fixnum_value(POLLNVAL));
  mrb_define_const (mrb, io_uring_class, "POLLOUT", mrb_fixnum_value(POLLOUT));
  mrb_define_const (mrb, io_uring_class, "POLLPRI", mrb_fixnum_value(POLLPRI));
  mrb_define_const (mrb, io_uring_class, "SHUT_RD", mrb_fixnum_value(SHUT_RD));
  mrb_define_const (mrb, io_uring_class, "SHUT_WR", mrb_fixnum_value(SHUT_WR));
  mrb_define_const (mrb, io_uring_class, "SHUT_RDWR", mrb_fixnum_value(SHUT_RDWR));
  mrb_define_const (mrb, io_uring_class, "AT_FDCWD", mrb_fixnum_value(AT_FDCWD));

  io_uring_error_class = mrb_define_class_under(mrb, io_uring_class, "Error", E_RUNTIME_ERROR);
  mrb_define_class_under(mrb, io_uring_class, "SQRingFullError",    io_uring_error_class);
  mrb_define_class_under(mrb, io_uring_class, "NoBuffersError",   io_uring_error_class);

  io_uring_buffers_class = mrb_define_class_under(mrb, io_uring_class, "_Buffers", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_buffers_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_buffers_class, "initialize", mrb_io_uring_buffers_init, MRB_ARGS_REQ(1));

  io_uring_open_how_class = mrb_define_class_under(mrb, io_uring_class, "OpenHow", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_open_how_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_open_how_class, "initialize", mrb_io_uring_open_how_init, MRB_ARGS_OPT(3));

  io_uring_op_class = mrb_define_class_under(mrb, io_uring_class, "Operation", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_op_class, MRB_TT_CDATA);
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_BUFFER",         mrb_fixnum_value(IORING_CQE_F_BUFFER));
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_MORE",           mrb_fixnum_value(IORING_CQE_F_MORE));
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_SOCK_NONEMPTY",  mrb_fixnum_value(IORING_CQE_F_SOCK_NONEMPTY));
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_NOTIF",          mrb_fixnum_value(IORING_CQE_F_NOTIF));
  mrb_define_const (mrb, io_uring_op_class, "SQE_IO_LINK",          mrb_fixnum_value(IOSQE_IO_LINK));
  
  io_uring_socket_operation_class = mrb_define_class_under(mrb, io_uring_class, "_SocketOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_socket_operation_class, "initialize",    mrb_io_uring_socket_operation_init,          MRB_ARGS_REQ(1));
  mrb_define_method(mrb, io_uring_socket_operation_class, "to_tcpsocket",  mrb_io_uring_operation_to_tcpsocket,         MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_socket_operation_class, "to_tcpserver",  mrb_io_uring_socket_operation_to_tcpserver,  MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_socket_operation_class, "to_udpsocket",  mrb_io_uring_socket_operation_to_udpsocket,  MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_socket_operation_class, "to_socket",     mrb_io_uring_socket_operation_to_socket,     MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_socket_operation_class, "to_unixsocket", mrb_io_uring_operation_to_unixsocket,        MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_socket_operation_class, "to_unixserver", mrb_io_uring_socket_operation_to_unixserver, MRB_ARGS_NONE());

  io_uring_accept_operation_class = mrb_define_class_under(mrb, io_uring_class, "_AcceptOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_accept_operation_class, "initialize",    mrb_io_uring_accept_operation_init,          MRB_ARGS_REQ(2));
  mrb_define_method(mrb, io_uring_accept_operation_class, "to_tcpsocket",  mrb_io_uring_operation_to_tcpsocket,         MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_accept_operation_class, "to_unixsocket", mrb_io_uring_operation_to_unixsocket,        MRB_ARGS_NONE());

  io_uring_multishot_accept_operation_class = mrb_define_class_under(mrb, io_uring_class, "_MultishotAcceptOp", io_uring_accept_operation_class);
  mrb_define_method(mrb, io_uring_multishot_accept_operation_class, "initialize", mrb_io_uring_multishot_accept_operation_init, MRB_ARGS_REQ(2));

  io_uring_recv_operation_class = mrb_define_class_under(mrb, io_uring_class, "_RecvOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_recv_operation_class, "initialize", mrb_io_uring_recv_operation_init, MRB_ARGS_REQ(3));

  io_uring_splice_operation_class = mrb_define_class_under(mrb, io_uring_class, "_SpliceOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_splice_operation_class, "initialize", mrb_io_uring_splice_operation_init, MRB_ARGS_REQ(3));

  io_uring_send_operation_class = mrb_define_class_under(mrb, io_uring_class, "_SendOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_send_operation_class, "initialize", mrb_io_uring_send_operation_init, MRB_ARGS_REQ(3));

  io_uring_shutdown_operation_class = mrb_define_class_under(mrb, io_uring_class, "_ShutdownOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_shutdown_operation_class, "initialize", mrb_io_uring_shutdown_operation_init, MRB_ARGS_REQ(1));

  io_uring_close_operation_class = mrb_define_class_under(mrb, io_uring_class, "_CloseOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_close_operation_class, "initialize", mrb_io_uring_close_operation_init, MRB_ARGS_REQ(2));

  io_uring_poll_add_operation_class = mrb_define_class_under(mrb, io_uring_class, "_PollAddOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_poll_add_operation_class, "initialize",  mrb_io_uring_poll_add_operation_init,  MRB_ARGS_REQ(2));
  mrb_define_method(mrb, io_uring_poll_add_operation_class, "readable?",   mrb_uring_readable, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_poll_add_operation_class, "writable?",   mrb_uring_writable, MRB_ARGS_NONE());

  io_uring_poll_multishot_operation_class = mrb_define_class_under(mrb, io_uring_class, "_PollMultishotOp", io_uring_poll_add_operation_class);
  mrb_define_method(mrb, io_uring_poll_multishot_operation_class, "initialize",  mrb_io_uring_poll_multishot_operation_init,  MRB_ARGS_REQ(2));

  io_uring_poll_update_operation_class = mrb_define_class_under(mrb, io_uring_class, "_PollUpdateOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_poll_update_operation_class, "initialize", mrb_io_uring_poll_update_operation_init, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, io_uring_poll_update_operation_class, "readable?",  mrb_uring_readable, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_poll_update_operation_class, "writable?",  mrb_uring_writable, MRB_ARGS_NONE());

  io_uring_openat2_operation_class = mrb_define_class_under(mrb, io_uring_class, "_OpenAt2Op", io_uring_op_class);
  mrb_define_method(mrb, io_uring_openat2_operation_class, "initialize",  mrb_io_uring_openat2_operation_init, MRB_ARGS_REQ(4));
  mrb_define_method(mrb, io_uring_openat2_operation_class, "to_file",     mrb_io_uring_openat2_to_file,        MRB_ARGS_NONE());

  io_uring_read_operation_class = mrb_define_class_under(mrb, io_uring_class, "_ReadOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_read_operation_class, "initialize", mrb_io_uring_read_operation_init, MRB_ARGS_REQ(3));

  io_uring_read_fixed_operation_class = mrb_define_class_under(mrb, io_uring_class, "_ReadFixedOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_read_fixed_operation_class, "initialize", mrb_io_uring_read_fixed_operation_init, MRB_ARGS_REQ(3));

  io_uring_write_operation_class = mrb_define_class_under(mrb, io_uring_class, "_WriteOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_write_operation_class, "initialize", mrb_io_uring_write_operation_init, MRB_ARGS_REQ(3));

  io_uring_cancel_operation_class = mrb_define_class_under(mrb, io_uring_class, "_CancelOp", io_uring_op_class);
  mrb_define_method(mrb, io_uring_cancel_operation_class, "initialize", mrb_io_uring_cancel_operation_init, MRB_ARGS_REQ(2));
}

void mrb_mruby_io_uring_gem_final(mrb_state* mrb) {}
