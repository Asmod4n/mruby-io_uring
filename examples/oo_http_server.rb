class HttpServer
    def initialize(port)
        @io_uring = IO::Uring.new
        @server = TCPServer.new(port)
        @read_open_how = OpenHow.new('r', 0, 'R')
        @files_dir = File.open(File.join(File.expand_path(File.dirname(__FILE__)), 'files'))
        @server.listen(4096)
        @io_uring.prep_multishot_accept(@server)
    end

    def run
        while true
            @io_uring.wait do |operation|
                if operation.errno
                    process_error(operation)
                    next
                end
                case operation.type
                when :multishot_accept
                    @io_uring.prep_recv(operation.sock).userdata = Connection.new(operation.sock)
                when :recv
                    process_recv(operation)
                when :openat2
                    process_openat2(operation)
                when :statx
                    process_statx(operation)
                when :read_fixed
                    process_read_fixed(operation)
                when :send
                    process_send(operation)
                end
            end
        end
    end

    private
    def process_error(operation)
        connection = nil
        filefd = nil

        case operation.userdata
        when Connection
            connection = operation.userdata
        when ReadFixedFileState
            connection = operation.userdata.connection
            filefd = operation.userdata.file
            @io_uring.return_used_buffer(operation)
        when SendFixedFileState
            connection = operation.userdata.connection
            filefd = operation.userdata.file
            @io_uring.return_used_buffer(operation.userdata.read_operation)
        when ReadFileState, SendFileState
            connection = operation.userdata.connection
            filefd = operation.userdata.file
        when SendBufState
            connection = operation.userdata.connection
        else
            puts operation.inspect
            raise operation.errno
        end

        error_file = "error_files/#{operation.errno.errno}.txt"
        if File.file? error_file
            error_page = File.read(error_file)
        else
            error_page = File.read("error_files/unknown_errno.txt")
        end

        @io_uring.prep_send(connection, error_page, IO::Uring::Operation::SQE_IO_LINK)
        @io_uring.prep_close(connection)
        if (filefd)
            @io_uring.prep_cancel_fd(filefd, IO::Uring::Operation::SQE_IO_LINK)
            @io_uring.prep_close(filefd)
        end
    end

    def process_disconnect(operation)
        case operation.userdata
        when ReadFileState, SendFileState
            @io_uring.prep_cancel_fd(operation.userdata)
        end
    end

    def process_recv(recv_operation)
        if recv_operation.res == 0
            process_disconnect(recv_operation)
            return
        end
        case recv_operation.userdata
        when Connection
            connection = recv_operation.userdata
            case connection.parse_request(recv_operation.buf)
            when :incomplete, :parser_error
                @io_uring.prep_close(connection)
                return
            when Integer
                path = connection.phr.path
                path = '/index.html' if (path == '/')
                connection = recv_operation.userdata
                @io_uring.prep_openat2(path, @files_dir, @read_open_how).userdata = connection
                connection.reset_phr
                @io_uring.prep_recv(recv_operation.sock).userdata = recv_operation.userdata
            end
        else
            puts operation.inspect
        end
    end

    def process_openat2(openat2_operation)
        connection = openat2_operation.userdata
        @io_uring.prep_statx(nil, openat2_operation.file).userdata = connection
    end

    def process_statx(statx_operation)
        connection = statx_operation.userdata
        @io_uring.prep_read_fixed(statx_operation.directory).userdata = ReadFixedFileState.new(connection, statx_operation.directory, statx_operation.statx.size)
    end

    def process_read_fixed(read_fixed_operation)
        read_fixed_state = read_fixed_operation.userdata
        read_fixed_state.already_read += read_fixed_operation.res
        @io_uring.prep_send(read_fixed_state.connection, read_fixed_operation.buf).userdata = SendFixedFileState.new(read_fixed_state.connection, read_fixed_operation)
        if (read_fixed_state.already_read < read_fixed_state.filesize)
            @io_uring.prep_read_fixed(read_fixed_operation.file, read_fixed_state.already_read).userdata = read_fixed_state
        else
            @io_uring.prep_close(read_fixed_state)
        end
    end

    def process_send(send_operation)
        if (send_operation.userdata)
            send_state = send_operation.userdata
            send_state.already_sent += send_operation.res
            if (send_state.already_sent < send_state.bufsize)
                @io_uring.prep_send(send_operation.connection, send_state.buf[send_state.already_sent..-1]).userdata = send_state
            else
                if send_state.is_a? SendFixedFileState
                    @io_uring.return_used_buffer(send_state.read_operation)
                end
            end
        end
    end
end

class Connection
    attr_reader :sock, :phr, :phr_status
    def initialize(sock)
        @sock = sock
        @phr = Phr.new
        @operations = {}
    end

    def parse_request(buf)
        @phr_status = @phr.parse_request(buf)
    end

    def reset_phr
        @phr.reset
    end

    alias_method :fileno, :sock
end

class ReadFileState
    attr_reader :connection, :file, :filesize
    attr_accessor :already_read
    def initialize(connection, file, filesize)
        @connection, @file, @filesize = connection, file, filesize
        @already_read = 0
    end

    alias_method :fileno, :file
end

class ReadFixedFileState < ReadFileState; end

class SendFileState
    attr_reader :connection, :read_operation, :file, :buf, :bufsize
    attr_accessor :already_sent
    def initialize(connection, read_operation)
        @connection, @read_operation, = connection, read_operation
        @file = read_operation.file
        @buf = read_operation.buf
        @bufsize = @buf.bytesize
        @already_sent = 0
    end

    alias_method :fileno, :file
end

class SendFixedFileState < SendFileState; end

class SendBufState
    attr_reader :connection, :buf, :bufsize
    attr_accessor :already_sent
    def initialize(connection, buf)
        @connection, @buf = connection, buf
        @bufsize = buf.bytesize
        @already_sent = 0
    end
end

HttpServer.new(3000).run
