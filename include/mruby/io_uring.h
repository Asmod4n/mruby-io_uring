#ifndef MRUBY_IO_URING_H
#define MRUBY_IO_URING_H

#include <mruby.h>

MRB_BEGIN_DECL

#define E_IO_URING_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "IO_Uring"), "Error"))
#define E_IO_URING_SQ_RING_FULL_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "IO_Uring"), "SQRingFullError"))

MRB_END_DECL

#endif
