# URING_AVAILABLE is set by mrb_mruby_io_uring_gem_init (src/mrb_io_uring.cpp,
# see the comment at its top) before mrblib loads. It names WHICH side of
# the slipstream seam answers this process: :native when the kernel's
# io_uring takes the syscalls, :shim when slipstream's engine does. Both
# are truthy - the seam always delivers, so the old false value is gone
# and nothing gates on the constant any more; it is reporting, for code
# (webmachine-mruby's startup banner, tests) that wants to know.
class IO::Uring
  class << self
    def default_io_uring
      @@default_io_uring ||= IO::Uring.new
    end

    def default_io_uring=(io_uring)
      @@default_io_uring = io_uring
    end
  end

  class Socket
    # IO::Uring.socket_for_fd (native) resolves TCPSocket/UNIXSocket/...
    # under IO::Uring via getsockname -- it needs to run with self
    # unambiguously IO::Uring itself for that, so this stays a thin
    # delegator rather than a second native binding on this class.
    def self.for_fd(fd)
      IO::Uring.socket_for_fd(fd)
    end
  end

  module UringSocketBase
    def recv_nonblock
      raise NotImplementedError
    end

    def recvfrom
      raise NotImplementedError
    end

    def send(buf, flags = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_send(self, buf, flags, sqe_flags, &block)
    end

    def recv(maxlen = 0, flags = 0, &block)
      IO::Uring.default_io_uring.prep_recv(self, maxlen, flags, &block)
    end
  end

  module ClientSocketMethods
    include UringSocketBase

    def connect(addrinfo, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_connect(self, addrinfo, sqe_flags, &block)
    end
  end

  module ServerSocketMethods
    include UringSocketBase

    def bind(addrinfo, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_bind(self, addrinfo, sqe_flags, &block)
    end

    def listen(backlog = SOMAXCONN, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_listen(self, backlog, sqe_flags, &block)
    end

    # IO::Uring::Socket.for_fd gives back the same async #send/#recv every
    # other io_uring socket has. Written back into #operation.sock itself --
    # #sock's post-completion value was just the bare accepted-fd Integer
    # anyway, still available via #fileno regardless of this.
    def accept(flags = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_accept(self, flags, sqe_flags) do |operation|
        operation.sock = IO::Uring.socket_for_fd(operation.res) unless operation.errno
        block.call(operation) if block
      end
    end

    def multishot_accept(flags = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_multishot_accept(self, flags, sqe_flags) do |operation|
        operation.sock = IO::Uring.socket_for_fd(operation.res) unless operation.errno
        block.call(operation) if block
      end
    end

    def sysaccept
      raise NotImplementedError
    end
  end

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

    def write_fixed(read_fixed_operation, offset = 0, sqe_flags = 0, &block)
      IO::Uring.default_io_uring.prep_write_fixed(self, read_fixed_operation, offset, sqe_flags, &block)
    end
  end

  class File < ::File
    # IO::Uring.file_for_fd (native) needs self unambiguously IO::Uring to
    # build the right nested class -- see socket_for_fd's identical reasoning.
    def self.for_fd(fd)
      IO::Uring.file_for_fd(fd)
    end

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
    include ClientSocketMethods
    include ServerSocketMethods
  end
end
