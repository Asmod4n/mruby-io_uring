class IO::Uring::Operation
  attr_reader :ring, :type, :sock, :fileno, :buf, :res, :flags, :errno, :poll_mask, :operation
  attr_accessor :userdata

  def buffer?
    flags & CQE_F_BUFFER != 0
  end

  def more?
    flags & CQE_F_MORE != 0
  end

  def sock_nonempty?
    flags & CQE_F_SOCK_NONEMPTY != 0
  end

  def notif?
    flags & CQE_F_NOTIF != 0
  end

  def socket(domain, type, protocol, flags = 0, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_socket(domain, type, protocol, flags, sqe_flags)
  end

  def accept(sock, flags = 0, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_accept(sock, flags, sqe_flags)
  end

  def multishot_accept(sock, flags = 0, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_multishot_accept(sock, flags, sqe_flags)
  end

  def recv(sock, len = 0, flags = 0, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_recv(sock, len, flags, sqe_flags)
  end

  def splice(fd_in, off_in, fd_out, off_out, nbytes, splice_flags, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_splice(fd_in, off_in, fd_out, off_out, nbytes, splice_flags, sqe_flags)
  end

  def send(sock, buf, flags = 0, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_send(sock, buf, flags, sqe_flags)
  end

  def shutdown(sock, how, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_shutdown(sock, how, sqe_flags)
  end

  def close(sock, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_close(sock, sqe_flags)
  end

  def poll_add(sock, poll_mask = IO::Uring::POLLIN, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_poll_add(sock, poll_mask, sqe_flags)
  end

  def poll_multishot(sock, poll_mask = IO::Uring::POLLIN, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_poll_multishot(sock, poll_mask, sqe_flags)
  end

  def poll_update(old_operation, poll_mask, flags, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_poll_update(old_operation, poll_mask, flags, sqe_flags)
  end

  def cancel(operation, flags = IO::Uring::ASYNC_CANCEL_ALL, sqe_flags = 0)
    sqe_flags |= SQE_IO_LINK
    ring.prep_cancel(operation, flags, sqe_flags)
  end
end
