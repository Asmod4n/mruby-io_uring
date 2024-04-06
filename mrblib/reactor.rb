class IO::Uring::Reactor
  @@mailbox = Hash.new({})
  @@uring = IO::Uring.new

  def self.accept(server)
    accept = @@mailbox[server][:accept]
    if accept && accept.size > 0
      accept.pop
    else
      @@uring.accept(server)
      handle_userdata(server)
      @@mailbox[server][:accept].pop
    end
  end

  def self.recv(socket)
    recv = @@mailbox[socket][:recv]
    if recv && recv.bytesize > 0
      recv.dup
    else
      @@uring.recv(socket)
      handle_userdata(socket)
      recv = @@mailbox[socket][:recv]
      recv.dup
    end
  ensure
    recv.clear
  end

  def self.send(socket, buf)
    total_send = 0
    send = @@mailbox[socket][:send]
    if send
      total_send += send
    end
    until total_send == buf.bytesize
      @@uring.send(socket, buf.byteslice(total_send..-1))
      handle_userdata(socket)
      total_send += @@mailbox[socket][:send]
    end
    total_send
  ensure
    @@mailbox[socket][:send] = 0
  end

  def self.close(socket)
    @@uring.close(socket)
    handle_userdata(socket)
  end

  def self.handle_userdata(socket)
    @@uring.wait do |userdata|
      raise userdata.errno if userdata.errno
      case userdata.type
      when :accept
        @@mailbox[userdata.sock] ||= {}
        @@mailbox[userdata.sock][:accept] ||= []
        @@mailbox[userdata.sock][:accept] << [userdata.res, userdata.addrlist]
      when :recv
        @@mailbox[userdata.sock] ||= {}
        @@mailbox[userdata.sock][:recv] ||= ""
        @@mailbox[userdata.sock][:recv] << userdata.buf
      when :send
        @@mailbox[userdata.sock] ||= {}
        @@mailbox[userdata.sock][:send] ||= 0
        @@mailbox[userdata.sock][:send] += userdata.res
      when :close
        @@mailbox.delete(userdata.sock)
      end
    end
    nil
  end
end
