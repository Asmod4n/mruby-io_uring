# mruby-io_uring

io_uring for mruby (WIP)

Requirements
============
This requires at least Linux 5.19

Installation
============
The gem is called mruby-io-uring for adding it to your project.
Since there are numerous versions of liburing around we are shipping a version which is compatible with this gem.

```ruby
conf.gem mgem: 'mruby-io-uring'
```
to your build_config.rb

Supported functions
===================

At the moment the following functions are implemented.
```c
io_uring_queue_init
io_uring_submit
io_uring_prep_socket
io_uring_prep_accept
io_uring_prep_accept_multishot
io_uring_prep_recv
io_uring_prep_splice
io_uring_prep_send
io_uring_prep_shutdown
io_uring_prep_close
io_uring_prep_poll_add
io_uring_prep_poll_multishot
io_uring_prep_openat2
io_uring_prep_read
io_uring_prep_read_fixed
io_uring_prep_write
io_uring_prep_cancel
io_uring_wait_cqe_timeout
```

Here is an example on how to use them (requires mruby-phr for http parsing)
-------------------------------------
```ruby
body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
server = TCPServer.new(12345)
server.listen(4096)
uring.prep_multishot_accept(server)

phr = Phr.new

while true
  uring.wait do |operation|
    raise operation.errno if operation.errno
    case operation.type
    when :multishot_accept
      puts "Remote Address: #{operation.to_tcpsocket.remote_address.inspect}"
      puts "Socket        : #{operation.res}"
      uring.prep_recv(operation.res)
      #operation.res  is the accepted socket
      #operation.sock is the socket passed to prep_accept, aka the server socket.
    when :recv
      next if operation.res == 0
      ret = phr.parse_request(operation.buf)
      case ret
      when :incomplete, :parser_error
        uring.prep_close(operation.sock)
        phr.reset
        next
      when Integer
        puts "HTTP Method   : #{phr.method}"
        puts "HTTP Version  : 1.#{phr.minor_version}"
        puts "HTTP Path     : #{phr.path}"
        puts "HTTP Headers  : #{phr.headers.inspect}"
        puts "HTTP Body     : #{operation.buf.byteslice(ret..-1).inspect}"
      end
      phr.reset
      uring.prep_send(operation.sock, response)
    when :send
      uring.prep_close(operation.sock)
    end
  end
end
```

uring.wait accepts a timeout as a float value, if a timeout occurs false is returned.

You can also use uring.wait without a block.
It returns an array which you can then iterate over.

API Docs
========

IO::Uring::OpenHow.new(flags = nil, mode = 0, resolve = nil)

### Supported Flags

- `r`: `O_RDONLY` (read-only)
- `w`: `O_WRONLY | O_CREAT | O_TRUNC` (write-only, create file if not exists, truncate if exists)
- `a`: `O_WRONLY | O_CREAT | O_APPEND` (append, create file if not exists)
- `+`: `O_RDWR` (read and write, must follow `r`, `w`, or `a`)
- `e`: `O_CLOEXEC` (close file descriptor on exec)
- `s`: `O_SYNC` (synchronize)
- `d`: `O_DIRECT` (direct access)
- `t`: `O_TMPFILE` (temporary file)
- `na`: `O_NOATIME` (do not update access time)
- `nc`: `O_NOCTTY` (do not assign controlling terminal)
- `nf`: `O_NOFOLLOW` (do not follow symbolic links)
- `nb`: `O_NONBLOCK` (non-blocking)
- `x`: `O_EXCL` (error if file exists)
- `D`: `O_DIRECTORY` (must be a directory)
- `P`: `O_PATH` (resolve pathname, do not open file)

### Supported Resolve

- `L`: `RESOLVE_NO_SYMLINKS` (do not follow symbolic links)
- `X`: `RESOLVE_NO_XDEV` (do not resolve across filesystem boundaries)
- `C`: `RESOLVE_CACHED` (use cached resolution)
- `B`: `RESOLVE_BENEATH` (resolve only beneath the directory)
- `R`: `RESOLVE_IN_ROOT` (perform resolution in root directory)


LICENSE
=======
Copyright 2024 Hendrik Beskow

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this project except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
