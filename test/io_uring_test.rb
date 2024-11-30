assert('File io') do
    io_uring = IO::Uring.new
    io_uring.prep_openat2('file.txt', File.open(File.expand_path(File.dirname(__FILE__))))

    io_uring.wait(1, 1) do |operation|
        assert_equal(operation.to_io.class, File)
        io_uring.prep_read(operation.file)
    end

    io_uring.wait(1, 1) do |operation|
        assert_equal(operation.buf, File.read(File.expand_path(File.dirname(__FILE__)) + '/file.txt'))
    end
end

assert ('Socket io') do
    io_uring = IO::Uring.new
    server = TCPServer.new(0)
    server.listen(4096)
    io_uring.prep_multishot_accept(server)
    io_uring.prep_socket(Socket::AF_INET, Socket::SOCK_STREAM)
    i = 5
    while i > 0
        num_cqes = io_uring.wait(1, 1) do |operation|
            assert_nil(operation.errno, operation.inspect)
            case operation.type
            when :socket
                assert_equal(operation.to_io.class, TCPSocket)
                io_uring.prep_connect(operation.sock, server.local_address.to_sockaddr)
            when :connect
                io_uring.prep_send(operation.sock, "hello")
            when :multishot_accept
                io_uring.prep_recv(operation.sock)
            when :send
                assert_equal(operation.res, "hello".bytesize)
            when :recv
                assert_equal(operation.buf, "hello")
            end
            i-=1
        end
        assert_equal(num_cqes.class, Integer)
    end
end
