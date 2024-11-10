#ifndef MRUBY_IO_URING_H
#define MRUBY_IO_URING_H

#include <mruby.h>
#ifdef MRB_INT16
#error "mruby-io_uring: MRB_INT16 is too small for mruby-io_uring"
#endif

MRB_BEGIN_DECL

#define E_IO_URING_ERROR (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "IO"), "Uring"), "Error"))
#define E_IO_URING_SQ_RING_FULL_ERROR (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "IO"), "Uring"), "SQRingFullError"))
#define E_IO_URING_NO_BUFFERS_ERROR (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "IO"), "Uring"), "NoBuffersError"))

MRB_END_DECL

#endif
