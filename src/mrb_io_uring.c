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
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sqes"), mrb_hash_new(mrb));
    return self;
  } else {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_queue_init");
  }
}

static struct io_uring_sqe *
mrb_io_uring_get_sqe(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) DATA_PTR(self);
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
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
  if (!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "SocketUserData"), 1, &self);
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
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }
  if (!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = { self, sock };
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "AcceptUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  mrb_io_uring_userdata_t *userdata_t = DATA_PTR(userdata);
  io_uring_prep_accept(sqe, mrb_fixnum(socket), (struct sockaddr*)&userdata_t->sa, &userdata_t->salen, (int) flags);
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
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a socket");
  }
  if(!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value buf = mrb_str_new_capa(mrb, len);
  mrb_value argv[] = {self, sock, buf};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "RecvUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_recv(sqe, mrb_fixnum(socket), RSTRING_PTR(buf), RSTRING_CAPA(buf), (int) flags);
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
  mrb_value fd_in_fd = mrb_check_convert_type(mrb, fd_in, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(fd_in_fd))) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a socket");
  }
  mrb_value fd_out_fd = mrb_check_convert_type(mrb, fd_out, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(fd_out_fd))) {
    mrb_raise(mrb, E_TYPE_ERROR, "third argument must be a socket");
  }
  if(!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = {self, fd_in, fd_out};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "SpliceUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_splice(sqe, mrb_fixnum(fd_in_fd), off_in, mrb_fixnum(fd_out_fd), off_out, nbytes, splice_flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, mrb_assoc_new(mrb, fd_in, fd_out));

  return self;
}

static mrb_value
mrb_io_uring_prep_send(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_int flags = 0;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "oo|id", &sock, &buf, &flags, &sqe, &mrb_io_uring_sqe_type);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a socket");
  }
  if (unlikely(!mrb_string_p(buf))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a string");
  }
  if(!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = {self, sock, buf};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "SendUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_send(sqe, mrb_fixnum(socket), RSTRING_PTR(buf), RSTRING_LEN(buf), (int) flags);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, buf);

  return self;
}

static mrb_value
mrb_io_uring_prep_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_int how = SHUT_RDWR;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "o|id", &sock, &how, &sqe, &mrb_io_uring_sqe_type);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a socket");
  }
  if(!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = { self, sock };
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "ShutdownUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_shutdown(sqe, mrb_fixnum(socket), how);
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, sock);

  return self;
}

static mrb_value
mrb_io_uring_prep_close(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  struct io_uring_sqe *sqe = NULL;
  mrb_get_args(mrb, "o|d", &sock, &sqe, &mrb_io_uring_sqe_type);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a socket");
  }
  if(!sqe) {
    sqe = mrb_io_uring_get_sqe(mrb, self);
  }

  mrb_value argv[] = { self, sock };
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "CloseUserData"), NELEMS(argv), argv);
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  io_uring_prep_close(sqe, mrb_fixnum(socket));
  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, sock);

  return self;
}

static mrb_value
mrb_io_uring_socket_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value ring_val;
  mrb_get_args(mrb, "o", &ring_val);
  if (unlikely(DATA_TYPE(ring_val) != &mrb_io_uring_queue_type)) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a uring");
  }
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
  if (unlikely(DATA_TYPE(ring_val) != &mrb_io_uring_queue_type)) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a uring");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);
  if(unlikely(!mrb_fixnum_p(mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }

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
  if (unlikely(DATA_TYPE(ring_val) != &mrb_io_uring_queue_type)) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a uring");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);
  if(unlikely(!mrb_fixnum_p(mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }
  if (unlikely(!mrb_string_p(buf))) {
    mrb_raise(mrb, E_TYPE_ERROR, "third argument must be a string");
  }

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
  if (unlikely(DATA_TYPE(ring_val) != &mrb_io_uring_queue_type)) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a uring");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);
  if(unlikely(!mrb_fixnum_p(mrb_check_convert_type(mrb, fd_in, MRB_TT_INTEGER, "Integer", "fileno")))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }
  if(unlikely(!mrb_fixnum_p(mrb_check_convert_type(mrb, fd_out, MRB_TT_INTEGER, "Integer", "fileno")))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }

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
  if (unlikely(DATA_TYPE(ring_val) != &mrb_io_uring_queue_type)) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a uring");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);
  if(unlikely(!mrb_fixnum_p(mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }
  if (unlikely(!mrb_string_p(buf))) {
    mrb_raise(mrb, E_TYPE_ERROR, "third argument must be a string");
  }

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
  if (unlikely(DATA_TYPE(ring_val) != &mrb_io_uring_queue_type)) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a uring");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);
  if(unlikely(!mrb_fixnum_p(mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }

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
  if (unlikely(DATA_TYPE(ring_val) != &mrb_io_uring_queue_type)) {
    mrb_raise(mrb, E_TYPE_ERROR, "first argument must be a uring");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "ring"), ring_val);
  if(unlikely(!mrb_fixnum_p(mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno")))) {
    mrb_raise(mrb, E_TYPE_ERROR, "second argument must be a socket");
  }

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = CLOSE;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "close")));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@sock"), sock);

  return self;
}

static mrb_value
sa2addrlist(mrb_state *mrb, const struct sockaddr *sa, socklen_t salen)
{
  mrb_value ary, host;
  unsigned short port;
  mrb_value afstr;

  switch (sa->sa_family) {
  case AF_INET:
    afstr = mrb_str_new_lit_frozen(mrb, "AF_INET");
    port = ((struct sockaddr_in*)sa)->sin_port;
    break;
  case AF_INET6:
    afstr = mrb_str_new_lit_frozen(mrb, "AF_INET6");
    port = ((struct sockaddr_in6*)sa)->sin6_port;
    break;
  default:
    mrb_raise(mrb, E_ARGUMENT_ERROR, "bad af");
    return mrb_nil_value();
  }
  port = ntohs(port);
  host = mrb_str_new_capa(mrb, NI_MAXHOST);
  if (unlikely(getnameinfo((struct sockaddr*)sa, salen, RSTRING_PTR(host), NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == -1))
    mrb_sys_fail(mrb, "getnameinfo");
  mrb_str_resize(mrb, host, strlen(RSTRING_PTR(host)));
  ary = mrb_ary_new_capa(mrb, 3);
  mrb_ary_push(mrb, ary, afstr);
  mrb_ary_push(mrb, ary, mrb_fixnum_value(port));
  mrb_ary_push(mrb, ary, host);
  return ary;
}

static mrb_value
mrb_io_uring_wait_cqe(mrb_state *mrb, mrb_value self)
{
  int rc = io_uring_submit(DATA_PTR(self));
  if (unlikely(rc < 0)) {
    errno = -rc;
    mrb_sys_fail(mrb, "io_uring_submit");
  }
  
  struct io_uring_cqe *cqe = NULL;
  rc = io_uring_wait_cqe(DATA_PTR(self), &cqe);
  if (likely(rc == 0)) {
    mrb_value userdata = mrb_obj_value(io_uring_cqe_get_data(cqe));
    mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@ret"), mrb_fixnum_value(cqe->res));
    mrb_io_uring_userdata_t *userdata_t = DATA_PTR(userdata);

    if(likely(cqe->res >= 0)) {
      switch(userdata_t->type) {
        case SOCKET:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@sock"), mrb_fixnum_value(cqe->res));
        break;
        case ACCEPT:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@sock"), mrb_fixnum_value(cqe->res));
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@addrlist"), sa2addrlist(mrb, (struct sockaddr*)&userdata_t->sa, userdata_t->salen));
        break;
        case RECV:
          mrb_str_resize(mrb, mrb_iv_get(mrb, userdata, mrb_intern_lit(mrb, "@buf")), cqe->res);
        break;
          default:
        break;
      }   
    } else {
      switch (userdata_t->type) {
        case SOCKET:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "socket_error")));
        break;
        case ACCEPT:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "accept_error")));
        break;
        case RECV:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "recv_error")));
        break;
        case SPLICE:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "splice_error")));
        break;
        case SEND:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "send_error")));
        break;
        case SHUTDOWN:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "shutdown_error")));
        break;
        case CLOSE:
          mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@type"), mrb_symbol_value(mrb_intern_lit(mrb, "close_error")));
        break;
      }
      mrb_value errno_val = mrb_fixnum_value(-cqe->res);
      mrb_iv_set(mrb, userdata, mrb_intern_lit(mrb, "@errno"), mrb_obj_new(mrb, mrb_class_get(mrb, "SystemCallError"), 1, &errno_val));
    }

    io_uring_cqe_seen(DATA_PTR(self), cqe);
    mrb_hash_delete_key(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata);

    return userdata;

  } else {
    errno = -rc;
    mrb_sys_fail(mrb, "io_uring_wait_cqe");
  }

  return self;
}

static mrb_value
mrb_uring_sqe_flags_get(mrb_state *mrb, mrb_value self)
{
  struct io_uring_sqe *sqe = DATA_PTR(self);
  return mrb_fixnum_value(sqe->flags);
}

static mrb_value
mrb_uring_sqe_flags_set(mrb_state *mrb, mrb_value self)
{
  struct io_uring_sqe *sqe = DATA_PTR(self);
  mrb_get_args(mrb, "i", &sqe->flags);

  return self;
}

static mrb_value
mrb_uring_sqe_io_link(mrb_state *mrb, mrb_value self)
{
  struct io_uring_sqe *sqe = DATA_PTR(self);
  sqe->flags |= IOSQE_IO_LINK;

  return self;
}

void
mrb_mruby_io_uring_gem_init(mrb_state* mrb)
{
  struct RClass *io_uring_class, *io_uring_error_class, *io_uring_sqe_class,
  *io_uring_userdata_class, *io_uring_socket_userdata_class,
  *io_uring_accept_userdata_class, *io_uring_recv_userdata_class,
  *io_uring_splice_userdata_class, *io_uring_send_userdata_class,
  *io_uring_shutdown_userdata_class, *io_uring_close_userdata_class;

  io_uring_class = mrb_define_class_under(mrb, mrb_class_get(mrb, "IO"), "Uring", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_class, "initialize",  mrb_io_uring_queue_init,    MRB_ARGS_OPT(2));
  mrb_define_method(mrb, io_uring_class, "sqe",         mrb_io_uring_get_sqe_m,     MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_class, "submit",      mrb_io_uring_submit,        MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_class, "socket",  	  mrb_io_uring_prep_socket,   MRB_ARGS_ARG(2, 3));
  mrb_define_method(mrb, io_uring_class, "accept",  	  mrb_io_uring_prep_accept,   MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "recv",  	    mrb_io_uring_prep_recv,     MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, io_uring_class, "splice",  	  mrb_io_uring_prep_splice,   MRB_ARGS_ARG(6, 1));
  mrb_define_method(mrb, io_uring_class, "send",  	    mrb_io_uring_prep_send,     MRB_ARGS_ARG(2, 2));
  mrb_define_method(mrb, io_uring_class, "shutdown",    mrb_io_uring_prep_shutdown, MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "close",  	    mrb_io_uring_prep_close,    MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, io_uring_class, "wait",  	    mrb_io_uring_wait_cqe,      MRB_ARGS_BLOCK());

  io_uring_sqe_class = mrb_define_class_under(mrb, io_uring_class, "Sqe", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_sqe_class, "flags", mrb_uring_sqe_flags_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_sqe_class, "flags=", mrb_uring_sqe_flags_set, MRB_ARGS_NONE());
  mrb_define_method(mrb, io_uring_sqe_class, "io_link", mrb_uring_sqe_io_link, MRB_ARGS_NONE());
  mrb_define_const (mrb, io_uring_sqe_class, "IO_LINK", mrb_fixnum_value(IOSQE_IO_LINK));

  io_uring_error_class = mrb_define_class_under(mrb, io_uring_class, "Error", E_RUNTIME_ERROR);
  mrb_define_class_under(mrb, io_uring_class, "SQRingFullError",  io_uring_error_class);

  io_uring_userdata_class = mrb_define_class_under(mrb, io_uring_class, "UserData", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_userdata_class, MRB_TT_CDATA);

  io_uring_socket_userdata_class = mrb_define_class_under(mrb, io_uring_class, "SocketUserData", io_uring_userdata_class);
  MRB_SET_INSTANCE_TT(io_uring_socket_userdata_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_socket_userdata_class, "initialize", mrb_io_uring_socket_userdata_init, MRB_ARGS_REQ(1));

  io_uring_accept_userdata_class = mrb_define_class_under(mrb, io_uring_class, "AcceptUserData", io_uring_userdata_class);
  MRB_SET_INSTANCE_TT(io_uring_accept_userdata_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_accept_userdata_class, "initialize", mrb_io_uring_accept_userdata_init, MRB_ARGS_REQ(2));

  io_uring_recv_userdata_class = mrb_define_class_under(mrb, io_uring_class, "RecvUserData", io_uring_userdata_class);
  MRB_SET_INSTANCE_TT(io_uring_recv_userdata_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_recv_userdata_class, "initialize", mrb_io_uring_recv_userdata_init, MRB_ARGS_REQ(2));

  io_uring_splice_userdata_class = mrb_define_class_under(mrb, io_uring_class, "SpliceUserData", io_uring_userdata_class);
  MRB_SET_INSTANCE_TT(io_uring_splice_userdata_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_splice_userdata_class, "initialize", mrb_io_uring_splice_userdata_init, MRB_ARGS_REQ(3));

  io_uring_send_userdata_class = mrb_define_class_under(mrb, io_uring_class, "SendUserData", io_uring_userdata_class);
  MRB_SET_INSTANCE_TT(io_uring_send_userdata_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_send_userdata_class, "initialize", mrb_io_uring_send_userdata_init, MRB_ARGS_REQ(2));

  io_uring_shutdown_userdata_class = mrb_define_class_under(mrb, io_uring_class, "ShutdownUserData", io_uring_userdata_class);
  MRB_SET_INSTANCE_TT(io_uring_shutdown_userdata_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_shutdown_userdata_class, "initialize", mrb_io_uring_shutdown_userdata_init, MRB_ARGS_REQ(1));

  io_uring_close_userdata_class = mrb_define_class_under(mrb, io_uring_class, "CloseUserData", io_uring_userdata_class);
  MRB_SET_INSTANCE_TT(io_uring_close_userdata_class, MRB_TT_CDATA);
  mrb_define_method(mrb, io_uring_close_userdata_class, "initialize", mrb_io_uring_close_userdata_init, MRB_ARGS_REQ(1));
}

void mrb_mruby_io_uring_gem_final(mrb_state* mrb) {}
