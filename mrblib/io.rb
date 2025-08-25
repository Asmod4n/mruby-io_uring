class IO::Uring
  class << self
    attr_accessor :default_io_uring
  end

  module UringSocketBase
    def recv_nonblock
      raise NotImplementedError
    end
    def recvfrom
      raise NotImplementedError
    end
  end

  # Für Clients wie TCPSocket, UNIXSocket
  module ClientSocketMethods
    include UringSocketBase

    def connect(addrinfo, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_connect(self, addrinfo, sqe_flags, &block)
    end

    def send(buf, flags = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_send(self, buf, flags, sqe_flags, &block)
    end

    def recv(maxlen = 0, flags = 0, &block)
      IO::Uring.default_io_uring.prep_recv(self, maxlen, flags, &block)
    end
  end

  # Für TCPServer, UNIXServer
  module ServerSocketMethods
    include UringSocketBase

    def bind(addrinfo, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_bind(self, addrinfo, sqe_flags, &block)
    end

    def listen(backlog = SOMAXCONN, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_listen(self, backlog, sqe_flags, &block)
    end

    def accept(flags = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_accept(self, flags, sqe_flags, &block)
    end

    def multishot_accept(flags = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_multishot_accept(self, flags, sqe_flags, &block)
    end

    def sysaccept
      raise NotImplementedError
    end
  end

  # Für UDP – kann sowohl binden als auch senden/empfangen
  module UDPSocketMethods
    include ClientSocketMethods

    def bind(addrinfo, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_bind(self, addrinfo, sqe_flags, &block)
    end
  end

  module UringFileMethods
    def read(nbytes = 0, offset = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_read(self, nbytes, offset, sqe_flags, &block)
    end

    def read_fixed(offset = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_read_fixed(self, offset, sqe_flags, &block)
    end

    def write(buf, offset = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_write(self, buf, offset, sqe_flags, &block)
    end
  end

  class File < ::File
    def initialize(fd_or_path, mode = nil, perm = -1, resolve = nil, sqe_flags = 0, &block)
      if fd_or_path.kind_of? Integer
        super(fd_or_path, mode)
      else
        @path = fd_or_path
        open_how = OpenHow.new(mode, perm, resolve)
        IO::Uring.default_io_uring.prep_openat2(fd_or_path, nil, open_how, sqe_flags) do |op|
          raise op.errno if op.errno
          super(op.fileno, op.open_how.flags)
          block.call(self) if block
        end
      end
    end
    include UringFileMethods
  end

  # Einbinden in passende Klassen
  class TCPSocket < ::TCPSocket
    include ClientSocketMethods
  end

  class UNIXSocket < ::UNIXSocket
    include ClientSocketMethods
  end

  class TCPServer < ::TCPServer
    include ServerSocketMethods
  end

  class UNIXServer < ::UNIXServer
    include ServerSocketMethods
  end

  class UDPSocket < ::UDPSocket
    include UDPSocketMethods
  end

  class Socket < ::Socket
    include UringSocketBase
    include ClientSocketMethods
    include ServerSocketMethods
  end
end
