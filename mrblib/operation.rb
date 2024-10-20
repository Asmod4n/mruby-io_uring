class IO::Uring::Operation
  attr_reader :ring, :type, :socket, :buf, :res, :flags, :errno, :poll_mask, :operation
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
end
