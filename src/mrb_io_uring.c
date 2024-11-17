#include "mrb_io_uring.h"

static mrb_value
mrb_io_uring_queue_init_params(mrb_state *mrb, mrb_value self)
{
  mrb_int entries = 2048, flags = 0;
  mrb_get_args(mrb, "|ii", &entries, &flags);
  if (unlikely(entries <= 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too few entries");
  }
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
  memset(mrb_io_uring, '\0', sizeof(*mrb_io_uring));
  mrb_data_init(self, mrb_io_uring, &mrb_io_uring_queue_type);
  mrb_io_uring->params.flags = flags;

  int ret = io_uring_queue_init_params((unsigned int) entries, &mrb_io_uring->ring, &mrb_io_uring->params);
  if (ret != 0) {
    memset(mrb_io_uring, '\0', sizeof(*mrb_io_uring));
    ret = io_uring_queue_init_params((unsigned int) entries, &mrb_io_uring->ring, &mrb_io_uring->params);
  }
  if (likely(ret == 0)) {
    if (can_use_buffers) {
      size_t max_buffers = limit.rlim_max / page_size;
      ret = io_uring_register_buffers_sparse(&mrb_io_uring->ring, max_buffers);
      if (likely(ret == 0)) {
        mrb_io_uring->sqes = mrb_hash_new_capa(mrb, entries);
        mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sqes"), mrb_io_uring->sqes);
        mrb_io_uring->allocated_buffers = 0;
        mrb_io_uring->max_buffers = max_buffers;
        mrb_io_uring->total_used_buffer_memory = 0;
        mrb_io_uring->memlock_limit = limit.rlim_max;
        mrb_io_uring->iovecs = (struct iovec *)mrb_calloc(mrb, mrb_io_uring->max_buffers, sizeof(*mrb_io_uring->iovecs));
        mrb_io_uring->tags = (unsigned long long *)mrb_calloc(mrb, mrb_io_uring->max_buffers, sizeof(*mrb_io_uring->tags));
        mrb_io_uring->calculated_sizes = (mrb_int *)mrb_calloc(mrb, mrb_io_uring->max_buffers, sizeof(*mrb_io_uring->calculated_sizes));
        mrb_io_uring->buffers = mrb_hash_new(mrb);
        mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "buffers"), mrb_io_uring->buffers);
        mrb_io_uring->free_list = mrb_hash_new(mrb);
        mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "free_list"), mrb_io_uring->free_list);
      } else {
        errno = -ret;
        mrb_sys_fail(mrb, "io_uring_register_buffers_sparse");      
      }
    }
    return self;
  } else {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_queue_init");
  }

  return self;
}

static mrb_io_uring_buffer_t
mrb_io_uring_buffer_get(mrb_state *mrb, mrb_io_uring_t *mrb_io_uring, mrb_int buffer_size)
{
  buffer_size = MIN(MAX(buffer_size, page_size), MAX_BUFFER_SIZE);
  size_t size_bin = precomputed_bins[(size_t) (buffer_size / page_size)];
  if (unlikely(mrb_io_uring->total_used_buffer_memory + size_bin > mrb_io_uring->memlock_limit)) {
    mrb_raise(mrb, E_RANGE_ERROR, "Total buffer memory would exceed RLIMIT_MEMLOCK limit");
  }

  mrb_value free_buffers = mrb_hash_get(mrb, mrb_io_uring->free_list, mrb_int_value(mrb, size_bin));
  if (mrb_array_p(free_buffers) && RARRAY_LEN(free_buffers) > 0) {
    mrb_int index = mrb_integer(mrb_ary_pop(mrb, free_buffers));
    mrb_io_uring_buffer_t result = {index, mrb_obj_value((void *) mrb_io_uring->tags[index])};
    return result;
  }

  if (mrb_io_uring->allocated_buffers < mrb_io_uring->max_buffers) {
    mrb_value buffer = mrb_str_new_capa(mrb, size_bin - 1);
    mrb_obj_freeze(mrb, buffer);

    mrb_io_uring->iovecs[mrb_io_uring->allocated_buffers].iov_base = RSTRING_PTR(buffer);
    mrb_io_uring->iovecs[mrb_io_uring->allocated_buffers].iov_len = size_bin;
    mrb_io_uring->tags[mrb_io_uring->allocated_buffers] = (uintptr_t)mrb_cptr(buffer);
    mrb_io_uring->calculated_sizes[mrb_io_uring->allocated_buffers] = size_bin;

    int ret = io_uring_register_buffers_update_tag(&mrb_io_uring->ring, mrb_io_uring->allocated_buffers, mrb_io_uring->iovecs, mrb_io_uring->tags, 1);
    if (likely(ret == 1)) {
      mrb_hash_set(mrb, mrb_io_uring->buffers, buffer, mrb_int_value(mrb, mrb_io_uring->allocated_buffers));
      mrb_io_uring->total_used_buffer_memory += size_bin;

      mrb_io_uring_buffer_t result = {mrb_io_uring->allocated_buffers++, buffer};
      return result;
    } else {
      errno = -ret;
      mrb_sys_fail(mrb, "io_uring_register_buffers_update_tag");
    }
  }

  mrb_raise(mrb, E_IO_URING_NO_BUFFERS_ERROR, "All fixed buffers are in use, you have to return them with ring.buffer_return(operation.buf) after you are done using them.");
}


static mrb_value
mrb_io_uring_buffer_return(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_value buffer;
  mrb_get_args(mrb, "S", &buffer);

  mrb_value index_val = mrb_hash_get(mrb, mrb_io_uring->buffers, buffer);
  if (unlikely(mrb_nil_p(index_val))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "buffer not found in buffers hash");
  }
  mrb_int calculated_size = mrb_io_uring->calculated_sizes[mrb_integer(index_val)];
  MRB_UNSET_FROZEN_FLAG(mrb_obj_ptr(buffer));
  mrb_str_resize(mrb, buffer, calculated_size - 1);
  mrb_obj_freeze(mrb, buffer);
  mrb_value size_bin = mrb_int_value(mrb, calculated_size);
  mrb_value free_buffers = mrb_hash_get(mrb, mrb_io_uring->free_list, size_bin);
  if (mrb_array_p(free_buffers)) {
    mrb_ary_push(mrb, free_buffers, index_val);
  } else {
    mrb_hash_set(mrb, mrb_io_uring->free_list, size_bin, mrb_ary_new_from_values(mrb, 1, &index_val));
  }

  return self;
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
    if (*flags_str == '+') {
      if (unlikely(seen_plus)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must be at the end with no characters following, and only once");
      }
      seen_plus = TRUE;
    } else if (unlikely(seen_plus)) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must be at the end with no characters following");
    }

    switch (*flags_str++) {
      case 'r':
        if (unlikely(read_mode || write_mode || append_mode)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        read_mode = TRUE;
        flags |= O_RDONLY;
        break;
      case 'w':
        if (unlikely(read_mode || write_mode || append_mode)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        write_mode = TRUE;
        flags |= O_WRONLY | O_CREAT | O_TRUNC;
        break;
      case 'a':
        if (unlikely(read_mode || write_mode || append_mode)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
        }
        append_mode = TRUE;
        flags |= O_WRONLY | O_CREAT | O_APPEND;
        break;
      case '+':
        if (unlikely(!(read_mode || write_mode || append_mode))) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "'+' must follow 'r', 'w', or 'a'");
        }
        flags = (flags & ~O_ACCMODE) | O_RDWR;
        break;
      case 'e':
        if (unlikely(flags & O_CLOEXEC)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'e' specified more than once");
        }
        flags |= O_CLOEXEC;
        break;
      case 's':
        if (unlikely(flags & O_SYNC)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 's' specified more than once");
        }
        flags |= O_SYNC;
        break;
      case 'd':
        if (unlikely(flags & O_DIRECT)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'd' specified more than once");
        }
        flags |= O_DIRECT;
        break;
      case 't':
        if (unlikely(flags & O_TMPFILE)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 't' specified more than once");
        }
        flags |= O_TMPFILE;
        break;
      case 'n':
        switch (*flags_str++) {
          case 'a':
            if (unlikely(flags & O_NOATIME)) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'na' specified more than once");
            }
            flags |= O_NOATIME;
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
          case 'b':
            if (unlikely(flags & O_NONBLOCK)) {
              mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'nb' specified more than once");
            }
            flags |= O_NONBLOCK;
            break;
          default:
            mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid flags string");
        }
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
      default:
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid flags string");
    }
  }

  // Final validation:
  if (unlikely(((flags & O_WRONLY) && (flags & O_RDWR)) || !(flags & (O_RDONLY | O_WRONLY | O_RDWR)))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid combination of flags");
  }

  return flags;
}

static __u64
mrb_io_uring_parse_resolve_string(mrb_state *mrb, mrb_value resolve)
{
  if (mrb_nil_p(resolve)) {
    return 0;
  }
  const char *resolve_str = mrb_string_value_cstr(mrb, &resolve);

  __u64 resolve_flags = 0;

  while (*resolve_str) {
    switch (*resolve_str++) {
      case 'L':
        if (unlikely(resolve_flags & RESOLVE_NO_SYMLINKS)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'L' specified more than once");
        }
        resolve_flags |= RESOLVE_NO_SYMLINKS;
        break;
      case 'X':
        if (unlikely(resolve_flags & RESOLVE_NO_XDEV)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'X' specified more than once");
        }
        resolve_flags |= RESOLVE_NO_XDEV;
        break;
      case 'C':
        if (unlikely(resolve_flags & RESOLVE_CACHED)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'C' specified more than once");
        }
        resolve_flags |= RESOLVE_CACHED;
        break;
      case 'B':
        if (unlikely(resolve_flags & RESOLVE_BENEATH)) {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "flag 'B' specified more than once");
        }
        resolve_flags |= RESOLVE_BENEATH;
        break;
      case 'R':
        if (unlikely(resolve_flags & RESOLVE_IN_ROOT)) {
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

static mrb_value
mrb_io_uring_prep_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int domain, type, protocol, flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "iii|ii", &domain, &type, &protocol, &flags, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, SOCKET),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "socket"))
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_socket(sqe, (int) domain, (int) type, (int) protocol, (unsigned int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &flags, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, ACCEPT),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "accept")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_accept(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  NULL, NULL,
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_multishot_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &flags, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, MULTISHOTACCEPT),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "multishot_accept")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_multishot_accept(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  NULL, NULL,
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
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

  mrb_value buf = mrb_str_new_capa(mrb, len);
  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = {
    mrb_int_value(mrb, RECV),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "recv")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock,
    mrb_symbol_value(mrb_intern_lit(mrb, "@buf")), buf
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_recv(sqe,
  sockfd,
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_splice(mrb_state *mrb, mrb_value self)
{
  mrb_value fd_in, fd_out;
  mrb_int off_in, off_out, nbytes, splice_flags, sqe_flags = 0;
  mrb_get_args(mrb, "oioiii|i", &fd_in, &off_in, &fd_out, &off_out, &nbytes, &splice_flags, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, SPLICE),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "splice")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), mrb_assoc_new(mrb, fd_in, fd_out)
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_splice(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, fd_in,  MRB_TT_INTEGER, "Integer", "fileno")), off_in,
  (int) mrb_integer(mrb_convert_type(mrb, fd_out, MRB_TT_INTEGER, "Integer", "fileno")), off_out,
  (unsigned int) nbytes, (unsigned int) splice_flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_send(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_int flags = 0, sqe_flags = 0;
  mrb_get_args(mrb, "oS|ii", &sock, &buf, &flags, &sqe_flags);

  mrb_obj_freeze(mrb, buf);
  mrb_value argv[] = {
    mrb_int_value(mrb, SEND),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "send")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock,
    mrb_symbol_value(mrb_intern_lit(mrb, "@buf")), buf
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_send(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int how, sqe_flags = 0;
  mrb_get_args(mrb, "oi|i", &sock, &how, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, SHUTDOWN),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "shutdown")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_shutdown(sqe, (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")), (int) how);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_close(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int sqe_flags = 0;
  mrb_get_args(mrb, "o|i", &sock, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, CLOSE),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "close")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_close(sqe, (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")));
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_add(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &poll_mask, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, POLLADD),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "poll_add")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock,
    mrb_symbol_value(mrb_intern_lit(mrb, "@poll_mask")), mrb_int_value(mrb, poll_mask)
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_poll_add(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (unsigned int) poll_mask);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  return operation;
}

static mrb_value
mrb_io_uring_prep_poll_multishot(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int poll_mask = POLLIN, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &poll_mask, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, POLLMULTISHOT),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "poll_multishot")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), sock,
    mrb_symbol_value(mrb_intern_lit(mrb, "@poll_mask")), mrb_int_value(mrb, poll_mask)
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_poll_multishot(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (unsigned int) poll_mask);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
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

  mrb_value argv[] = {
    mrb_int_value(mrb, POLLUPDATE),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "poll_update")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@sock")), mrb_iv_get(mrb, old_operation, mrb_intern_lit(mrb, "@sock")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@poll_mask")), mrb_int_value(mrb, poll_mask),
    mrb_symbol_value(mrb_intern_lit(mrb, "@userdata")), mrb_iv_get(mrb, old_operation, mrb_intern_lit(mrb, "@userdata"))
  };
  mrb_value new_operation;
  new_operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(new_operation));
  io_uring_prep_poll_update(sqe,
  (uintptr_t) mrb_ptr(old_operation), (uintptr_t) mrb_ptr(new_operation),
  (unsigned int) poll_mask, (unsigned int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
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
    open_how = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "OpenHow"), 0, NULL);
  }

  mrb_value argv[] = {
    mrb_int_value(mrb, OPENAT2),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "openat2")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@path")), path,
    mrb_symbol_value(mrb_intern_lit(mrb, "@directory")), directory,
    mrb_symbol_value(mrb_intern_lit(mrb, "@open_how")), open_how
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_openat2(sqe, dfd, mrb_string_value_cstr(mrb, &path), mrb_data_get_ptr(mrb, open_how, &mrb_io_uring_open_how_type));
  mrb_obj_freeze(mrb, path);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
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

  if (nbytes <= 0) {
    struct stat st;
    if (likely(fstat(filefd, &st)) == 0) {
        nbytes = st.st_size;
    } else {
      mrb_sys_fail(mrb, "fstat");
    }
  }

  mrb_value buf = mrb_str_new_capa(mrb, nbytes);
  mrb_value argv[] = {
    mrb_int_value(mrb, READ),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "read")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@file")), file,
    mrb_symbol_value(mrb_intern_lit(mrb, "@buf")), buf
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_read(sqe,
  filefd,
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (unsigned long long) offset);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);
  mrb_obj_freeze(mrb, buf);

  return operation;
}

static mrb_value
mrb_io_uring_prep_read_fixed(mrb_state *mrb, mrb_value self)
{
  mrb_value file;
  mrb_int buffer_size = MRB_IORING_DEFAULT_FIXED_BUFFER_SIZE, offset = 0, sqe_flags = 0;
  mrb_get_args(mrb, "o|iii", &file, &buffer_size, &offset, &sqe_flags);
  int fd = (int) mrb_integer(mrb_convert_type(mrb, file, MRB_TT_INTEGER, "Integer", "fileno"));

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_io_uring_buffer_t buffer_t = mrb_io_uring_buffer_get(mrb, mrb_io_uring, buffer_size);

  mrb_int index = buffer_t.index;
  mrb_value buf = buffer_t.buffer;

  mrb_value argv[] = {
    mrb_int_value(mrb, READFIXED),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "read_fixed")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@file")), file,
    mrb_symbol_value(mrb_intern_lit(mrb, "@buf")), buf
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_read_fixed(sqe,
    fd,
    mrb_io_uring->iovecs[index].iov_base, RSTRING_CAPA(buf) + 1,
    (unsigned long long) offset, index);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);
  mrb_obj_freeze(mrb, buf);

  return operation;
}

static mrb_value
mrb_io_uring_prep_write(mrb_state *mrb, mrb_value self)
{
  mrb_value file, buf;
  mrb_int offset, sqe_flags = 0;
  mrb_get_args(mrb, "oSi|i", &file, &buf, &offset, &sqe_flags);

  mrb_value argv[] = {
    mrb_int_value(mrb, WRITE),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "write")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@file")), file,
    mrb_symbol_value(mrb_intern_lit(mrb, "@buf")), buf
  };
  mrb_value operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(operation));
  io_uring_prep_write(sqe,
  (int) mrb_integer(mrb_convert_type(mrb, file, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (__u64) offset);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);

  mrb_hash_set(mrb, mrb_io_uring->sqes, operation, operation);

  mrb_obj_freeze(mrb, buf);

  return operation;
}

static mrb_value
mrb_io_uring_prep_cancel(mrb_state *mrb, mrb_value self)
{
  mrb_value operation;
  mrb_int flags = IORING_ASYNC_CANCEL_ALL, sqe_flags = 0;
  mrb_get_args(mrb, "o|ii", &operation, &flags, &sqe_flags);
  mrb_data_check_type(mrb, operation, &mrb_io_uring_operation_type);

  mrb_value argv[] = {
    mrb_int_value(mrb, CANCEL),
    mrb_symbol_value(mrb_intern_lit(mrb, "@ring")), self,
    mrb_symbol_value(mrb_intern_lit(mrb, "@type")), mrb_symbol_value(mrb_intern_lit(mrb, "cancel")),
    mrb_symbol_value(mrb_intern_lit(mrb, "@operation")), operation
  };
  mrb_value cancel_operation = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Operation"), NELEMS(argv), argv);

  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, &mrb_io_uring->ring);
  io_uring_sqe_set_data(sqe, mrb_ptr(cancel_operation));
  io_uring_prep_cancel(sqe, mrb_ptr(operation), (int) flags);
  io_uring_sqe_set_flags(sqe, (unsigned int) sqe_flags);
  mrb_hash_set(mrb, mrb_io_uring->sqes, cancel_operation, cancel_operation);

  return cancel_operation;
}

static mrb_value
mrb_io_uring_operation_class_init(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_int argc;
  mrb_get_args(mrb, "*", &argv, &argc);

  if (unlikely(argc < 1 || argc % 2 == 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "expecting an odd number of arguments; operation type followed by key-value pairs");
  }

  mrb_int type = mrb_integer(argv[0]);
  if (unlikely(type < 0 || type > LAST_TYPE)) {
    mrb_raise(mrb, E_RANGE_ERROR, "type isn't enum mrb_io_uring_op_types");
  }

  enum mrb_io_uring_op_types *operation_type = mrb_realloc(mrb, DATA_PTR(self), sizeof(*operation_type));
  mrb_data_init(self, operation_type, &mrb_io_uring_operation_type);
  *operation_type = type;

  for (mrb_int i = 1; i < argc; i += 2) {
    mrb_value key = argv[i];
    mrb_value value = argv[i + 1];

    if (unlikely(!mrb_symbol_p(key))) {
      mrb_raise(mrb, E_TYPE_ERROR, "expected symbol for key");
    }

    mrb_iv_set(mrb, self, mrb_symbol(key), value);
  }

  return self;
}

static mrb_value
mrb_io_uring_operation_to_tcpserver(mrb_state *mrb, mrb_value self)
{
  mrb_value sock = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@sock"));
  mrb_value tcp_server = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "TCPServer")), "for_fd", 1, sock);
  (void) mrb_io_fileno(mrb, tcp_server);
  ((struct mrb_io *)DATA_PTR(tcp_server))->close_fd = 0;
  return tcp_server;
}

static mrb_value
mrb_io_uring_operation_to_udpsocket(mrb_state *mrb, mrb_value self)
{
  mrb_value sock = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@sock"));
  mrb_value udp_socket = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "UDPSocket")), "for_fd", 1, sock);
  (void) mrb_io_fileno(mrb, udp_socket);
  ((struct mrb_io *)DATA_PTR(udp_socket))->close_fd = 0;
  return udp_socket;
}

static mrb_value
mrb_io_uring_operation_to_socket(mrb_state *mrb, mrb_value self)
{
  mrb_value sock = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@sock"));
  sock = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "Socket")), "for_fd", 1, sock);
  (void) mrb_io_fileno(mrb, sock);
  ((struct mrb_io *)DATA_PTR(sock))->close_fd = 0;
  return sock;
}

static mrb_value
mrb_io_uring_operation_to_unixserver(mrb_state *mrb, mrb_value self)
{
  mrb_value sock = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@sock"));
  mrb_value unix_server = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "UNIXServer")), "for_fd", 1, sock);
  (void) mrb_io_fileno(mrb, unix_server);
  ((struct mrb_io *)DATA_PTR(unix_server))->close_fd = 0;
  return unix_server;
}

static mrb_value
mrb_io_uring_operation_to_tcpsocket(mrb_state *mrb, mrb_value self)
{
  mrb_value sock = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@sock"));
  mrb_value tcp_socket = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "TCPSocket")), "for_fd", 1, sock);
  (void) mrb_io_fileno(mrb, tcp_socket);
  ((struct mrb_io *)DATA_PTR(tcp_socket))->close_fd = 0;
  return tcp_socket;
}

static mrb_value
mrb_io_uring_operation_to_unixsocket(mrb_state *mrb, mrb_value self)
{
  mrb_value sock = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@sock"));
  mrb_value unix_socket = mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "UNIXSocket")), "for_fd", 1, sock);
  (void) mrb_io_fileno(mrb, unix_socket);
  ((struct mrb_io *)DATA_PTR(unix_socket))->close_fd = 0;
  return unix_socket;
}

static mrb_value
mrb_io_uring_operation_to_file(mrb_state *mrb, mrb_value self)
{
  mrb_value file = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@file"));
  file = mrb_obj_new(mrb, mrb_class_get(mrb, "File"), 1, &file);
  (void) mrb_io_fileno(mrb, file);
  ((struct mrb_io *)DATA_PTR(file))->close_fd = 0;
  return file;
}

static mrb_value
mrb_io_uring_process_cqe(mrb_state *mrb, struct io_uring_cqe *cqe)
{
  mrb_value operation = mrb_obj_value(io_uring_cqe_get_data(cqe));
  enum mrb_io_uring_op_types *operation_t = DATA_PTR(operation);
  mrb_value res = mrb_int_value(mrb, cqe->res);
  mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@res"), res);
  mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@flags"), mrb_int_value(mrb, cqe->flags));

  if (likely(cqe->res >= 0)) {
    switch(*operation_t) {
      case SOCKET:
        mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@sock"), res);
      break;
      case OPENAT2: {
        mrb_iv_set(mrb, operation, mrb_intern_lit(mrb, "@file"), res);
        mrb_value path = mrb_iv_get(mrb, operation, mrb_intern_lit(mrb, "@path"));
        if (unlikely(!mrb_string_p(path))) {
          mrb_raise(mrb, E_TYPE_ERROR, "path is not a string");
        }
        MRB_UNSET_FROZEN_FLAG(mrb_obj_ptr(path));
      } break;
      case RECV:
      case READ:
      case READFIXED: {
        mrb_value buf = mrb_iv_get(mrb, operation, mrb_intern_lit(mrb, "@buf"));
        if (likely(mrb_string_p(buf))) {
          MRB_UNSET_FROZEN_FLAG(mrb_obj_ptr(buf));
          mrb_str_resize(mrb, buf, cqe->res);
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
mrb_io_uring_iterate_over_cqes(mrb_state *mrb, mrb_value self, mrb_io_uring_t *mrb_io_uring, mrb_value block, struct io_uring_cqe *cqe)
{
  unsigned head;
  unsigned int i = 0;

  if (mrb_type(block) == MRB_TT_PROC) {
    struct mrb_jmpbuf* prev_jmp = mrb->jmp;
    struct mrb_jmpbuf c_jmp;
    int arena_index = mrb_gc_arena_save(mrb);
    MRB_TRY(&c_jmp)
    {
      mrb->jmp = &c_jmp;
      io_uring_for_each_cqe(&mrb_io_uring->ring, head, cqe) {
        mrb_value operation = mrb_io_uring_process_cqe(mrb, cqe);
        mrb_yield(mrb, block, operation);
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

    return self;
  } else {
    mrb_value operations = mrb_ary_new_capa(mrb, mrb_hash_size(mrb, mrb_io_uring->sqes));
    int arena_index = mrb_gc_arena_save(mrb);
    io_uring_for_each_cqe(&mrb_io_uring->ring, head, cqe) {
      mrb_value operation = mrb_io_uring_process_cqe(mrb, cqe);
      mrb_ary_push(mrb, operations, operation);
      if (!(cqe->flags & IORING_CQE_F_MORE)) {
        mrb_hash_delete_key(mrb, mrb_io_uring->sqes, operation);
      }
      mrb_gc_arena_restore(mrb, arena_index);
      i++;
    }
    io_uring_cq_advance(&mrb_io_uring->ring, i);

    return operations;
  }
}

static mrb_value
mrb_io_uring_submit_and_wait_timeout(mrb_state *mrb, mrb_value self)
{
  mrb_io_uring_t *mrb_io_uring = DATA_PTR(self);

  mrb_int wait_nr = 1;
  mrb_float timeout = -1.0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "|if&", &wait_nr, &timeout, &block);

  int rc;
  struct io_uring_cqe *cqe = NULL;
  if (timeout >= 0.0) {
    timeout += 0.5e-9; // we are adding this so ts can't become negative.
    struct __kernel_timespec ts = {
      .tv_sec  = timeout,
      .tv_nsec = (timeout - (mrb_int)(timeout)) * NSEC_PER_SEC
    };
    rc = io_uring_submit_and_wait_timeout(&mrb_io_uring->ring, &cqe, wait_nr, &ts, NULL);
  } else {
    rc = io_uring_submit_and_wait_timeout(&mrb_io_uring->ring, &cqe, wait_nr, NULL, NULL);
  }

  if (rc < 0) {
    errno = -rc;
    if (likely(errno == ETIME))
      return mrb_false_value();
    mrb_sys_fail(mrb, "io_uring_submit_and_wait_timeout");
  }

  return mrb_io_uring_iterate_over_cqes(mrb, self, mrb_io_uring, block, cqe);
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
  pthread_mutex_lock(&mutex);
  if (gem_load_count++ == 0) {
    page_size = sysconf(_SC_PAGESIZE);
    size_t num_bins = (MAX_BUFFER_SIZE / page_size) + 1;
    precomputed_bins = (size_t *)calloc(num_bins, sizeof(size_t));
    if (likely(precomputed_bins)) {
      for (size_t i = 0; i < num_bins; ++i) {
        size_t size = i * page_size;
        precomputed_bins[i] = (size_t)pow(2, ceil(log2(size < page_size ? page_size : size)));
      }
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
    } else {
      pthread_mutex_unlock(&mutex);
      mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
    }
  } else if (unlikely(!precomputed_bins)) {
      pthread_mutex_unlock(&mutex);
      mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));    
  }
  pthread_mutex_unlock(&mutex);

  struct RClass *io_uring_class, *io_uring_error_class, *io_uring_op_class, *io_uring_open_how_class;

  io_uring_class = mrb_define_class_under(mrb, mrb_class_get(mrb, "IO"), "Uring", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_class, "initialize",              mrb_io_uring_queue_init_params,       MRB_ARGS_OPT(2));
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
if (can_use_buffers) {
  mrb_define_method(mrb, io_uring_class, "prep_read_fixed",         mrb_io_uring_prep_read_fixed,         MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "buffer_return",  	        mrb_io_uring_buffer_return,           MRB_ARGS_REQ(1));
}
  mrb_define_method(mrb, io_uring_class, "prep_write",  	          mrb_io_uring_prep_write,              MRB_ARGS_ARG(3, 1));
  mrb_define_method(mrb, io_uring_class, "prep_cancel",  	          mrb_io_uring_prep_cancel,             MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "wait",  	                mrb_io_uring_submit_and_wait_timeout, MRB_ARGS_OPT(2)|MRB_ARGS_BLOCK());
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

  io_uring_open_how_class = mrb_define_class_under(mrb, io_uring_class, "OpenHow", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_open_how_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_open_how_class, "initialize", mrb_io_uring_open_how_init, MRB_ARGS_OPT(3));

  io_uring_op_class = mrb_define_class_under(mrb, io_uring_class, "Operation", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_op_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_op_class, "initialize",           mrb_io_uring_operation_class_init, MRB_ARGS_ANY());
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_BUFFER",         mrb_fixnum_value(IORING_CQE_F_BUFFER));
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_MORE",           mrb_fixnum_value(IORING_CQE_F_MORE));
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_SOCK_NONEMPTY",  mrb_fixnum_value(IORING_CQE_F_SOCK_NONEMPTY));
  mrb_define_const (mrb, io_uring_op_class, "CQE_F_NOTIF",          mrb_fixnum_value(IORING_CQE_F_NOTIF));
  mrb_define_const (mrb, io_uring_op_class, "SQE_IO_LINK",          mrb_fixnum_value(IOSQE_IO_LINK));
  mrb_define_method(mrb, io_uring_op_class, "to_tcpsocket",         mrb_io_uring_operation_to_tcpsocket,  MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "to_tcpserver",         mrb_io_uring_operation_to_tcpserver,  MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "to_udpsocket",         mrb_io_uring_operation_to_udpsocket,  MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "to_socket",            mrb_io_uring_operation_to_socket,     MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "to_unixsocket",        mrb_io_uring_operation_to_unixsocket, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "to_unixserver",        mrb_io_uring_operation_to_unixserver, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "to_file",              mrb_io_uring_operation_to_file,       MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "readable?",            mrb_uring_readable, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_op_class, "writable?",            mrb_uring_writable, MRB_ARGS_NONE());
}

void
mrb_mruby_io_uring_gem_final(mrb_state* mrb)
{
  pthread_mutex_lock(&mutex);

  if (gem_load_count > 0 && --gem_load_count == 0) {
    free(precomputed_bins);
    precomputed_bins = NULL;
  }

  pthread_mutex_unlock(&mutex);
}
