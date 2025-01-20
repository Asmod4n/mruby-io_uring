#pragma once

#include <mruby.h>
#if defined MRB_INT16 || MRB_INT_BIT < 32
#error "mruby-io_uring: MRB_INT16 is too small for mruby-io_uring"
#endif

MRB_BEGIN_DECL

#define E_IO_URING_ERROR (mrb_class_get_under_(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "IO"), "Uring"), "Error"))
#define E_IO_URING_SQ_RING_FULL_ERROR (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "IO"), "Uring"), "SQRingFullError"))

MRB_END_DECL
