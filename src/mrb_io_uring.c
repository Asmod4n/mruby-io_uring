#include "mrb_io_uring.h"

static mrb_value
mrb_io_uring_queue_init(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*ring));
  mrb_data_init(self, ring, &mrb_io_uring_queue_type);

  mrb_int entries = 2048, flags = 0;
  mrb_get_args(mrb, "|ii", &entries, &flags);

  int ret = io_uring_queue_init(entries, ring, flags);
  if (likely(ret == 0)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sqes"), mrb_hash_new_capa(mrb, entries));
    return self;
  } else {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_queue_init");
  }
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
mrb_io_uring_get_sqe_m(mrb_state *mrb, mrb_value self)
{
  return mrb_obj_value(Data_Wrap_Struct(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Sqe"), &mrb_io_uring_sqe_type, mrb_io_uring_get_sqe(mrb, self)));
}

static mrb_value
mrb_io_uring_submit(mrb_state *mrb, mrb_value self)
{
  int ret = io_uring_submit(DATA_PTR(self));
  if (unlikely(ret < 0)) {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_submit");
  }

  return self;
}

static mrb_value
mrb_io_uring_prep_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int domain, type, protocol = 0, flags = 0;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "ii|iid", &domain, &type, &protocol, &flags, &sqe, &mrb_io_uring_sqe_type);
  if (likely(!sqe)) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_SocketUserData"), 1, &self);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_socket(sqe, domain, type, protocol, flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, mrb_true_value());

  return self;
}

static mrb_value
mrb_io_uring_prep_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int flags = 0;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "o|id", &sock, &flags, &sqe, &mrb_io_uring_sqe_type);
  if (likely(!sqe)) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = { self, sock };
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_AcceptUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  mrb_io_uring_userdata_t *userdata_t = DATA_PTR(userdata);

  io_uring_prep_accept(sqe,
  mrb_fixnum(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  (struct sockaddr*)&userdata_t->sa, &userdata_t->salen,
  (int) flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, sock);

  return self;
}

static mrb_value
mrb_io_uring_prep_recv(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int len = 9000, flags = 0;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "o|iid", &sock, &len, &flags, &sqe, &mrb_io_uring_sqe_type);
  if (likely(!sqe)) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value buf = mrb_str_new_capa(mrb, len);
  mrb_value argv[] = {self, sock, buf};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_RecvUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));

  io_uring_prep_recv(sqe,
  mrb_fixnum(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_CAPA(buf),
  (int) flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, buf);

  return self;
}

static mrb_value
mrb_io_uring_prep_splice(mrb_state *mrb, mrb_value self)
{
  mrb_value fd_in, fd_out;
  mrb_int off_in, off_out, nbytes, splice_flags;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "oioiii|d", &fd_in, &off_in, &fd_out, &off_out, &nbytes, &splice_flags, &sqe, &mrb_io_uring_sqe_type);
  if (!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = {self, fd_in, fd_out};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_SpliceUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));

  io_uring_prep_splice(sqe,
  mrb_fixnum(mrb_convert_type(mrb, fd_in, MRB_TT_INTEGER, "Integer", "fileno")), off_in,
  mrb_fixnum(mrb_convert_type(mrb, fd_out, MRB_TT_INTEGER, "Integer", "fileno")), off_out,
  nbytes, splice_flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, mrb_assoc_new(mrb, fd_in, fd_out));


  return self;
}

static mrb_value
mrb_io_uring_prep_send(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_int flags = 0;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "oS|id", &sock, &buf, &flags, &sqe, &mrb_io_uring_sqe_type);
  if (likely(!sqe)) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = {self, sock, buf};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_SendUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));

  io_uring_prep_send(sqe,
  mrb_fixnum(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")),
  RSTRING_PTR(buf), RSTRING_LEN(buf),
  (int) flags);

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, buf);

  return self;
}

static mrb_value
mrb_io_uring_prep_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int how = SHUT_WR;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "o|id", &sock, &how, &sqe, &mrb_io_uring_sqe_type);
  if (likely(!sqe)) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = { self, sock };
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_ShutdownUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_shutdown(sqe, mrb_fixnum(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")), how);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, sock);

  return self;
}

static mrb_value
mrb_io_uring_prep_close(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "o|d", &sock, &sqe, &mrb_io_uring_sqe_type);
  if (likely(!sqe)) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = { self, sock };
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_CloseUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_close(sqe, mrb_fixnum(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")));
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, sock);

  return self;
}

static mrb_value
mrb_io_uring_prep_poll_add(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  struct io_uring_sqe *sqe = NULL;
  mrb_int poll_mask = POLL_IN;
  mrb_get_args(mrb, "o|id", &sock, &poll_mask, &sqe, &mrb_io_uring_sqe_type);
  if (likely(!sqe)) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = { self, sock };
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "_PollAddUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_poll_add(sqe, mrb_fixnum(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")), poll_mask);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, sock);

  return self;
}

static mrb_value
mrb_io_uring_socket_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val;
  mrb_get_args(mrb, "o", &ring_val);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = SOCKET;
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "socket")));

  return self;
}

static mrb_value
mrb_io_uring_accept_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = ACCEPT;
  userdata->salen = sizeof(userdata->sa);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "accept")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
mrb_io_uring_recv_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock, buf;
  mrb_get_args(mrb, "ooo", &ring_val, &sock, &buf);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = RECV;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "recv")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@buf"),  buf);

  return self;
}

static mrb_value
mrb_io_uring_splice_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, fd_in, fd_out;
  mrb_get_args(mrb, "ooo", &ring_val, &fd_in, &fd_out);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = SPLICE;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "splice")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), mrb_assoc_new(mrb, fd_in, fd_out));

  return self;
}

static mrb_value
mrb_io_uring_send_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock, buf;
  mrb_get_args(mrb, "ooo", &ring_val, &sock, &buf);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = SEND;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "send")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@buf"),  buf);

  return self;
}

static mrb_value
mrb_io_uring_shutdown_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = SHUTDOWN;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "shutdown")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
mrb_io_uring_close_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = CLOSE;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "close")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
mrb_io_uring_poll_add_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val, sock;
  mrb_get_args(mrb, "oo", &ring_val, &sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = POLLADD;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "poll_add")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
sa2addrlist(mrb_state *mrb, const struct sockaddr *sa, socklen_t salen)
{
  mrb_sym afstr;
  in_port_t port;

  switch (sa->sa_family) {
  case AF_INET:
    afstr = mrb_intern_lit(mrb, "AF_INET");
    port = ((struct sockaddr_in*)sa)->sin_port;
    break;
  case AF_INET6:
    afstr = mrb_intern_lit(mrb, "AF_INET6");
    port = ((struct sockaddr_in6*)sa)->sin6_port;
    break;
  default:
    mrb_raise(mrb, E_ARGUMENT_ERROR, "bad af");
    return mrb_nil_value();
  }
  port = ntohs(port);
  mrb_value host = mrb_str_new_capa(mrb, NI_MAXHOST);
  if (unlikely(getnameinfo((struct sockaddr*)sa, salen, RSTRING_PTR(host), NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == -1))
    mrb_sys_fail(mrb, "getnameinfo");
  mrb_str_resize(mrb, host, strlen(RSTRING_PTR(host)));
  mrb_value ary = mrb_ary_new_capa(mrb, 3);
  mrb_ary_push(mrb, ary, mrb_symbol_value(afstr));
  mrb_ary_push(mrb, ary, mrb_fixnum_value(port));
  mrb_ary_push(mrb, ary, host);
  return ary;
}

static mrb_value
mrb_io_uring_process_cqe(mrb_state *mrb, struct io_uring_cqe *cqe)
{
  mrb_value userdata = mrb_obj_value(io_uring_cqe_get_data(cqe));
  mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@res"), mrb_fixnum_value(cqe->res));
  mrb_io_uring_userdata_t *userdata_t = DATA_PTR(userdata);

  if (likely(cqe->res >= 0)) {
    switch(userdata_t->type) {
      case SOCKET:
        mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@sock"), mrb_fixnum_value(cqe->res));
      break;
      case ACCEPT:
        mrb_iv_set(mrb, userdata,
        mrb_intern_lit(mrb, "@addrlist"),
        sa2addrlist(mrb, (struct sockaddr*)&userdata_t->sa, userdata_t->salen));
      break;
      case RECV:
        mrb_str_resize(mrb, mrb_iv_get(mrb, userdata, mrb_intern_lit(mrb, "@buf")), cqe->res);
      break;
      default:
      break;
    }   
  } else {
    mrb_value errno_val = mrb_fixnum_value(-cqe->res);
    mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@errno"), mrb_obj_new(mrb, mrb_class_get(mrb, "SystemCallError"), 1, &errno_val));
  }

  return userdata;
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

  mrb_float timeout = 0.0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "|f&", &timeout, &block);

  struct io_uring_cqe *cqe = NULL;
  if (timeout > 0.0) {
    timeout += 0.5e-9;
    struct __kernel_timespec ts = {
      ts.tv_sec  = timeout,
      ts.tv_nsec = (timeout - (long)(timeout)) * NSEC_PER_SEC
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

  unsigned head;
  unsigned i = 0;
  mrb_value sqes = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes"));
  if (mrb_block_given_p(mrb)) {
    int arena_index = mrb_gc_arena_save(mrb);
    io_uring_for_each_cqe(ring, head, cqe) {
      mrb_value userdata = mrb_io_uring_process_cqe(mrb, cqe);
      mrb_yield(mrb, block, userdata);
      mrb_hash_delete_key(mrb, sqes, userdata);
      mrb_gc_arena_restore(mrb, arena_index);
      i++;
    }
    io_uring_cq_advance(ring, i);
  } else {
    mrb_value userdatas = mrb_ary_new_capa(mrb, mrb_hash_size(mrb, sqes));
    int arena_index = mrb_gc_arena_save(mrb);
    io_uring_for_each_cqe(ring, head, cqe) {
      mrb_value userdata = mrb_io_uring_process_cqe(mrb, cqe);
      mrb_ary_push(mrb, userdatas, userdata);
      mrb_hash_delete_key(mrb, sqes, userdata);
      mrb_gc_arena_restore(mrb, arena_index);
      i++;
    }
    io_uring_cq_advance(ring, i);

    return userdatas;
  }

  return self;
}

static mrb_value
mrb_uring_sqe_flags_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct io_uring_sqe *) DATA_PTR(self))->flags);
}

static mrb_value
mrb_uring_sqe_flags_set(mrb_state *mrb, mrb_value self)
{
  mrb_get_args(mrb, "i", &((struct io_uring_sqe *) DATA_PTR(self))->flags);
  return self;
}

static mrb_value
mrb_uring_sqe_io_link(mrb_state *mrb, mrb_value self)
{
  ((struct io_uring_sqe *) DATA_PTR(self))->flags |= IOSQE_IO_LINK;

  return self;
}

void
mrb_mruby_io_uring_gem_init(mrb_state* mrb)
{
  struct RClass *io_uring_class, *io_uring_error_class, *io_uring_sqe_class,
  *io_uring_userdata_class, *io_uring_socket_userdata_class,
  *io_uring_accept_userdata_class, *io_uring_recv_userdata_class,
  *io_uring_splice_userdata_class, *io_uring_send_userdata_class,
  *io_uring_shutdown_userdata_class, *io_uring_close_userdata_class,
  *io_uring_poll_add_userdata_class;

  io_uring_class = mrb_define_class_under(mrb, mrb_class_get(mrb, "IO"), "Uring", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_class, "initialize",  mrb_io_uring_queue_init,      MRB_ARGS_OPT(2));
  mrb_define_method(mrb, io_uring_class, "sqe",         mrb_io_uring_get_sqe_m,       MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_class, "submit",      mrb_io_uring_submit,          MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_class, "socket",  	  mrb_io_uring_prep_socket,     MRB_ARGS_ARG(2, 3));
  mrb_define_method(mrb, io_uring_class, "accept",  	  mrb_io_uring_prep_accept,     MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "recv",  	    mrb_io_uring_prep_recv,       MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, io_uring_class, "splice",  	  mrb_io_uring_prep_splice,     MRB_ARGS_ARG(6, 1));
  mrb_define_method(mrb, io_uring_class, "send",  	    mrb_io_uring_prep_send,       MRB_ARGS_ARG(2, 2));
  mrb_define_method(mrb, io_uring_class, "shutdown",    mrb_io_uring_prep_shutdown,   MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "close",  	    mrb_io_uring_prep_close,      MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, io_uring_class, "poll_add",  	mrb_io_uring_prep_poll_add,   MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "wait",  	    mrb_io_uring_wait_cqe_timeout,MRB_ARGS_OPT(1));

  io_uring_sqe_class = mrb_define_class_under(mrb, io_uring_class, "Sqe", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_sqe_class, "flags",   mrb_uring_sqe_flags_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_sqe_class, "flags=",  mrb_uring_sqe_flags_set, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_sqe_class, "io_link", mrb_uring_sqe_io_link, MRB_ARGS_NONE());
  mrb_define_const (mrb, io_uring_sqe_class, "IO_LINK", mrb_fixnum_value(IOSQE_IO_LINK));

  io_uring_error_class = mrb_define_class_under(mrb, io_uring_class, "Error", E_RUNTIME_ERROR);
  mrb_define_class_under(mrb, io_uring_class, "SQRingFullError",  io_uring_error_class);

  io_uring_userdata_class = mrb_define_class_under(mrb, io_uring_class, "UserData", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_userdata_class, MRB_TT_CDATA);

  io_uring_socket_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_SocketUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_socket_userdata_class, "initialize", mrb_io_uring_socket_userdata_init, MRB_ARGS_REQ(1));

  io_uring_accept_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_AcceptUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_accept_userdata_class, "initialize", mrb_io_uring_accept_userdata_init, MRB_ARGS_REQ(2));

  io_uring_recv_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_RecvUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_recv_userdata_class, "initialize", mrb_io_uring_recv_userdata_init, MRB_ARGS_REQ(3));

  io_uring_splice_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_SpliceUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_splice_userdata_class, "initialize", mrb_io_uring_splice_userdata_init, MRB_ARGS_REQ(3));

  io_uring_send_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_SendUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_send_userdata_class, "initialize", mrb_io_uring_send_userdata_init, MRB_ARGS_REQ(3));

  io_uring_shutdown_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_ShutdownUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_shutdown_userdata_class, "initialize", mrb_io_uring_shutdown_userdata_init, MRB_ARGS_REQ(1));

  io_uring_close_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_CloseUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_close_userdata_class, "initialize", mrb_io_uring_close_userdata_init, MRB_ARGS_REQ(2));

  io_uring_poll_add_userdata_class = mrb_define_class_under(mrb, io_uring_class, "_PollAddUserData", io_uring_userdata_class);
  mrb_define_method(mrb, io_uring_poll_add_userdata_class, "initialize", mrb_io_uring_poll_add_userdata_init, MRB_ARGS_REQ(2));
}

void mrb_mruby_io_uring_gem_final(mrb_state* mrb) {}
