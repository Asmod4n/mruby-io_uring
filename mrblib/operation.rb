class IO::Uring::Operation
  attr_reader :ring, :type, :sock, :client_sock, :poll_mask, :file, :directory, :operation, :res, :flags, :errno
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

  def fileno
    if @sock
      @sock.fileno
    elsif @file
      @file.fileno
    elsif @client_sock
      @client_sock.fileno
    else
      nil
    end
  end

  def inspect
    attrs = {
      ring: @ring,
      type: @type,
      sock: @sock,
      addrinfo: addrinfo,
      buf: buf,
      poll_mask: @poll_mask,
      file: @file,
      path: path,
      directory: @directory,
      open_how: open_how,
      statx: statx,
      operation: @operation,
      res: @res,
      flags: @flags,
      errno: @errno,
      userdata: @userdata
    }

    existing_attrs = attrs.reject { |_, v| v.nil? }
    attr_str = existing_attrs.map { |k, v| "#{k}=#{v.inspect}" }.join(", ")
    "#<#{self.class}: #{attr_str}>"
  end
end
