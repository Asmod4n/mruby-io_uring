#include "mrb_io_uring.h"

static mrb_value
mrb_io_uring_queue_init(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*ring));
  memset(ring, 0, sizeof(*ring));
  mrb_data_init(self, ring, &mrb_io_uring_queue_type);

  mrb_int entries = 512, flags = 0;
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

MRB_INLINE struct io_uring_sqe *
mrb_io_uring_get_sqe(mrb_state *mrb, struct io_uring *ring)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (unlikely(!sqe)) {
    mrb_raise(mrb, E_IO_URING_SQ_RING_FULL_ERROR, "SQ ring is currently full and entries must be submitted for processing before new ones can get allocated");
  }
  return sqe;
}

MRB_INLINE mrb_value
mrb_io_uring_submit(mrb_state *mrb, mrb_value self, struct io_uring *ring, struct io_uring_sqe *sqe, mrb_value obj, mrb_value userdata)
{
  io_uring_sqe_set_data(sqe, mrb_ptr(userdata));
  int ret = io_uring_submit(ring);
  if (unlikely(ret <= 0)) {
    errno = -ret;
    mrb_sys_fail(mrb, "io_uring_submit");
  }

  mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata, obj);

  return mrb_int_value(mrb, ret);
}

static mrb_value
mrb_io_socket_class_init(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_get_args(mrb, "o", &sock);
  if(unlikely(!mrb_fixnum_p(sock))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a socket");
  }

  int *socket = mrb_realloc(mrb, DATA_PTR(self), sizeof(int));
  mrb_int s = mrb_fixnum(sock);
  memcpy(socket, &s, sizeof(int));
  
  mrb_data_init(self, socket, &mrb_io_uring_socket_type);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@fileno"), sock);

  return self;
}

static mrb_value
mrb_io_uring_prep_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int port, domain = AF_INET, type = SOCK_STREAM, protocol = 0 , flags = 0;
  mrb_get_args(mrb, "i|iiii", &port, &domain, &type, &protocol, &flags);

  struct io_uring *ring = (struct io_uring *) DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, ring);
  mrb_value port_val = mrb_int_value(mrb, port);
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "SocketUserData"), 1, &port_val);

  io_uring_prep_socket(sqe, domain, type, protocol, flags);

  return mrb_io_uring_submit(mrb, self, ring, sqe, port_val, userdata);
}

static mrb_value
mrb_io_uring_prep_accept(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, ring);
  mrb_value sock;
  mrb_int flags = 0;
  mrb_get_args(mrb, "o|i", &sock, &flags);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a socket");
  }

  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "AcceptUserData"), 1, &sock);
  mrb_io_uring_userdata_t *userdata_t = DATA_PTR(userdata);
  io_uring_prep_accept(sqe, mrb_fixnum(socket), (struct sockaddr*)&userdata_t->sa, &userdata_t->salen, (int) flags);

  return mrb_io_uring_submit(mrb, self, ring, sqe, sock, userdata);
}

static mrb_value
mrb_io_uring_prep_recv(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, ring);

  mrb_value sock;
  mrb_int len = 4096, flags = 0;
  mrb_get_args(mrb, "o|ii", &sock, &len, &flags);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a socket");
  }

  mrb_value buf = mrb_str_new_capa(mrb, len);
  mrb_value argv[] = {sock, buf};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "RecvUserData"), sizeof(argv) / sizeof(argv[0]), argv);
  io_uring_prep_recv(sqe, mrb_fixnum(socket), RSTRING_PTR(buf), RSTRING_CAPA(buf), (int) flags);

  return mrb_io_uring_submit(mrb, self, ring, sqe, buf, userdata);
}

static mrb_value
mrb_io_uring_prep_send(mrb_state *mrb, mrb_value self)
{
  struct io_uring *ring = (struct io_uring *) DATA_PTR(self);
  struct io_uring_sqe *sqe = mrb_io_uring_get_sqe(mrb, ring);

  mrb_value sock, buf;
  mrb_int flags = 0;
  mrb_get_args(mrb, "oS|i", &sock, &buf, &flags);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a socket");
  }

  mrb_value argv[] = {sock, buf};
  mrb_value userdata = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "SendUserData"), sizeof(argv) / sizeof(argv[0]), argv);
  io_uring_prep_send(sqe, mrb_fixnum(socket), RSTRING_PTR(buf), RSTRING_LEN(buf), (int) flags);

  return mrb_io_uring_submit(mrb, self, ring, sqe, buf, userdata);
}

static mrb_value
mrb_io_uring_socket_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_int port;
  mrb_get_args(mrb, "i", &port);

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = TCPSERVER;
  userdata->type_sym = mrb_symbol_value(mrb_intern_lit(mrb, "tcpserver"));
  userdata->socket = 0;
  userdata->port = port;
  memset(&userdata->sa, '\0', sizeof(struct sockaddr_storage));
  userdata->salen = 0;

  return self;
}

static mrb_value
mrb_io_uring_accept_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value sock;
  mrb_get_args(mrb, "o", &sock);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a socket");
  }

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = ACCEPT;
  userdata->type_sym = mrb_symbol_value(mrb_intern_lit(mrb, "accept"));
  userdata->socket = mrb_fixnum(socket);
  userdata->port = 0;
  memset(&userdata->sa, '\0', sizeof(struct sockaddr_storage));
  userdata->salen = sizeof(struct sockaddr_storage);

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sock"), sock);

  return self;
}


static mrb_value
mrb_io_uring_recv_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_get_args(mrb, "oS", &sock, &buf);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a socket");
  }

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = RECV;
  userdata->type_sym = mrb_symbol_value(mrb_intern_lit(mrb, "recv"));
  userdata->socket = mrb_fixnum(socket);
  userdata->port = 0;
  memset(&userdata->sa, '\0', sizeof(struct sockaddr_storage));
  userdata->salen = 0;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "buf"), buf);

  return self;
}

static mrb_value
mrb_io_uring_send_userdata_init(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, buf;
  mrb_get_args(mrb, "oS", &sock, &buf);
  mrb_value socket = mrb_check_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno");
  if(unlikely(!mrb_fixnum_p(socket))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a socket");
  }

  mrb_io_uring_userdata_t *userdata = mrb_realloc(mrb, DATA_PTR(self), sizeof(*userdata));
  mrb_data_init(self, userdata, &mrb_io_uring_userdata_type);
  userdata->type = SEND;
  userdata->type_sym = mrb_symbol_value(mrb_intern_lit(mrb, "send"));
  userdata->socket = mrb_fixnum(socket);
  userdata->port = 0;
  memset(&userdata->sa, '\0', sizeof(struct sockaddr_storage));
  userdata->salen = 0;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sock"), sock);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "buf"), buf);

  return self;
}

void setup_listening_socket(int sock, int port) {
    struct sockaddr_in srv_addr;

    int enable = 1;
    int rc = setsockopt(sock,
                   SOL_SOCKET, SO_REUSEADDR,
                   &enable, sizeof(int));
    err(EXIT_FAILURE, NULL);

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* We bind to a port and turn this socket into a listening
     * socket.
     * */
    rc = bind(sock,
             (const struct sockaddr *)&srv_addr,
             sizeof(srv_addr));

    assert(rc == 0 && "bind");

    rc = listen(sock, 1024);
    assert(rc == 0 && "listen");

}

static mrb_value
sa2addrlist(mrb_state *mrb, const struct sockaddr *sa, socklen_t salen)
{
  mrb_value ary, host;
  unsigned short port;
  const char *afstr;

  switch (sa->sa_family) {
  case AF_INET:
    afstr = "AF_INET";
    port = ((struct sockaddr_in*)sa)->sin_port;
    break;
  case AF_INET6:
    afstr = "AF_INET6";
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
  mrb_ary_push(mrb, ary, mrb_str_new_cstr(mrb, afstr));
  mrb_ary_push(mrb, ary, mrb_fixnum_value(port));
  mrb_ary_push(mrb, ary, host);
  return ary;
}

static mrb_value
mrb_io_uring_wait_cqe(mrb_state *mrb, mrb_value self)
{
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "&", &block);
  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(mrb_type(block) != MRB_TT_PROC)) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }

  struct io_uring_cqe *cqe;
  int rc = io_uring_wait_cqe(DATA_PTR(self), &cqe);
  if (likely(rc == 0)) {
    if(cqe->res < 0) {
      errno = -cqe->res;
      mrb_sys_fail(mrb, "io_uring_wait_cqe");
    }
    mrb_value userdata = mrb_obj_value(io_uring_cqe_get_data(cqe));
    mrb_io_uring_userdata_t *userdata_t = DATA_PTR(userdata);
    mrb_value ret = mrb_nil_value();

    switch(userdata_t->type) {
      case TCPSERVER: {
        setup_listening_socket(cqe->res, userdata_t->port);
        mrb_value sock = mrb_int_value(mrb, cqe->res);
        ret = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Socket"), 1, &sock);
      } break;
      case ACCEPT: {
        mrb_value sock = mrb_int_value(mrb, cqe->res);
        ret = mrb_obj_new(mrb, mrb_class_get_under(mrb, mrb_class(mrb, self), "Socket"), 1, &sock);
        //mrb_iv_set(mrb, ret, mrb_intern_lit(mrb, "@sa"), sa2addrlist(mrb, (struct sockaddr*)&userdata_t->sa, userdata_t->salen));
      } break;
      case RECV: {
        mrb_value buf = mrb_iv_get(mrb, userdata, mrb_intern_lit(mrb, "buf"));
        mrb_str_resize(mrb, buf, cqe->res);
        ret = mrb_assoc_new(mrb, mrb_iv_get(mrb, userdata, mrb_intern_lit(mrb, "sock")), buf);        
      } break;
      case SEND: {
        ret = mrb_assoc_new(mrb, mrb_iv_get(mrb, userdata, mrb_intern_lit(mrb, "sock")), mrb_int_value(mrb, cqe->res));
      } break;
    }

    mrb_value argv[] = {userdata_t->type_sym, ret};
    mrb_yield_argv(mrb, block, sizeof(argv) / sizeof(argv[0]), argv);
    mrb_hash_delete_key(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "sqes")), userdata);
    io_uring_cqe_seen(DATA_PTR(self), cqe);
  } else {
    errno = -rc;
    mrb_sys_fail(mrb, "io_uring_wait_cqe");
  }

  return self;
}

void
mrb_mruby_io_uring_gem_init(mrb_state* mrb)
{ 
  struct RClass *io_uring_class, *io_uring_error_class, *io_uring_socket_class, *io_uring_socket_userdata_class, *io_uring_accept_userdata_class, *io_uring_recv_userdata_class, *io_uring_send_userdata_class;
  io_uring_class = mrb_define_class(mrb, "IO_Uring", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_class, MRB_TT_DATA);
  mrb_define_method(mrb, io_uring_class, "initialize",  mrb_io_uring_queue_init,    MRB_ARGS_OPT(2));
  mrb_define_method(mrb, io_uring_class, "socket",  	  mrb_io_uring_prep_socket,   MRB_ARGS_REQ(5));
  mrb_define_method(mrb, io_uring_class, "accept",  	  mrb_io_uring_prep_accept,   MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, io_uring_class, "recv",  	    mrb_io_uring_prep_recv,     MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, io_uring_class, "send",  	    mrb_io_uring_prep_send,     MRB_ARGS_ARG(2, 1));
  mrb_define_method(mrb, io_uring_class, "wait",  	    mrb_io_uring_wait_cqe,      MRB_ARGS_NONE());

  io_uring_error_class = mrb_define_class_under(mrb, io_uring_class, "Error", E_RUNTIME_ERROR);
  mrb_define_class_under(mrb, io_uring_class, "SQRingFullError", io_uring_error_class);

  io_uring_socket_class = mrb_define_class_under(mrb, io_uring_class, "Socket", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_socket_class, MRB_TT_DATA);
  mrb_define_method(mrb, io_uring_socket_class, "initialize", mrb_io_socket_class_init, MRB_ARGS_REQ(1));

  io_uring_socket_userdata_class = mrb_define_class_under(mrb, io_uring_class, "SocketUserData", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_socket_userdata_class, MRB_TT_DATA);
  mrb_define_method(mrb, io_uring_socket_userdata_class, "initialize", mrb_io_uring_socket_userdata_init, MRB_ARGS_REQ(1));

  io_uring_accept_userdata_class = mrb_define_class_under(mrb, io_uring_class, "AcceptUserData", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_accept_userdata_class, MRB_TT_DATA);
  mrb_define_method(mrb, io_uring_accept_userdata_class, "initialize", mrb_io_uring_accept_userdata_init, MRB_ARGS_REQ(1));

  io_uring_recv_userdata_class = mrb_define_class_under(mrb, io_uring_class, "RecvUserData", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_recv_userdata_class, MRB_TT_DATA);
  mrb_define_method(mrb, io_uring_recv_userdata_class, "initialize", mrb_io_uring_recv_userdata_init, MRB_ARGS_REQ(1));

  io_uring_send_userdata_class = mrb_define_class_under(mrb, io_uring_class, "SendUserData", mrb->object_class);
  MRB_SET_INSTANCE_TT(io_uring_send_userdata_class, MRB_TT_DATA);
  mrb_define_method(mrb, io_uring_send_userdata_class, "initialize", mrb_io_uring_send_userdata_init, MRB_ARGS_REQ(1));
}

void mrb_mruby_io_uring_gem_final(mrb_state* mrb) {}
