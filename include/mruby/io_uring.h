#ifndef MRUBY_IO_URING_H
#define MRUBY_IO_URING_H

#include <mruby.h>

MRB_BEGIN_DECL

#define E_IO_URING_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "IO_Uring"), "Error"))
#define E_IO_URING_SOCKET_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "IO_Uring"), "SocketError"))
#define E_IO_URING_ACCEPT_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "IO_Uring"), "AcceptError"))
#define E_IO_URING_RECV_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "IO_Uring"), "RecvError"))
#define E_IO_URING_SEND_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "IO_Uring"), "SendError"))
#define E_IO_URING_CLOSE_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "IO_Uring"), "CloseError"))
#define E_IO_URING_SQ_RING_FULL_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "IO_Uring"), "SQRingFullError"))

MRB_END_DECL

#endif
