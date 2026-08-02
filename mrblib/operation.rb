# See the top of io.rb (and mrb_io_uring.cpp) for what URING_AVAILABLE is
# and why this guard exists: without it, `class IO; class Uring; ...` below
# would add an Operation class -- and, unlike io.rb's `class IO::Uring`
# form, this one doesn't even require IO::Uring to already exist first, so
# it would define IO::Uring::Operation with real, working attr_readers
# regardless of native availability.
if URING_AVAILABLE

class IO
  class Uring
    class Operation
      attr_reader :ring, :type, :splice_socks, :poll_mask, :file, :fileno, :directory, :operation, :res, :flags, :errno
      attr_accessor :userdata

      # A plain writer, not just attr_reader, so ServerSocketMethods#accept
      # (io.rb) can upgrade #sock from the bare accepted-fd Integer the
      # native layer sets it to into the properly classed, async-capable
      # TCPSocket/UNIXSocket/... instance #to_io/.for_fd already knows how
      # to build. The raw fd stays available via #fileno regardless.
      attr_accessor :sock

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

      def inspect
        attrs = {
          ring: @ring,
          type: @type,
          sock: @sock,
          splice_socks: @splice_socks,
          addrinfo: addrinfo,
          buf: buf,
          poll_mask: @poll_mask,
          file: @file,
          fileno: @fileno,
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
  end
end

end # URING_AVAILABLE
