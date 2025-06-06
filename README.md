# mruby-io_uring

io_uring for mruby (WIP)

Requirements
============
This is only working with a linux kernel.

Installation
============
The gem is called mruby-io-uring for adding it to your project, here is an example.

```ruby
conf.gem mgem: 'mruby-io-uring'
```
to add it to your build_config.rb

Since there are numerous versions of liburing around we are shipping a version which is compatible with this gem.

String ownership
----------------

Functions which end in _fixed use a internal and private buffer pool, those buffers are mruby Strings and belong to the ring, not to you, they are frozen at all times and you musn't change their contents.

When you are done with a fixed buffer you have to return them to the ring with ring.return_used_buffer(operation), take a look at the file_benchmark.rb in the example dir for a example.
Performance of _fixed functions can be much higher.

Every other function which takes a string argument freezes that string till io_uring has processed it and given back to you in a ring.wait block, where its unfrozen. If you gave the ring a frozen string, it returns frozen back to you.


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
      puts "Remote Address: #{operation.to_io.remote_address.inspect}"
      puts "Socket        : #{operation.res}"
      uring.prep_recv(operation.sock)
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

uring.wait accepts two arguments, the number of operations to wait for, by default 1, and a timeout as a float value, if a timeout occurs false is returned.


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

### Modes

Modes are those you would also use with chmod, aka 0666 to create a file which is read and writable by everyone.
Take a look at https://en.wikipedia.org/wiki/Chmod for more info, only the numeric modes are supported as of now.

### Supported Resolve

- `L`: `RESOLVE_NO_SYMLINKS` (do not follow symbolic links)
- `X`: `RESOLVE_NO_XDEV` (do not resolve across filesystem boundaries)
- `C`: `RESOLVE_CACHED` (use cached resolution)
- `B`: `RESOLVE_BENEATH` (resolve only beneath the directory)
- `R`: `RESOLVE_IN_ROOT` (perform resolution in root directory)

Operations
==========

Using a ring.prep function retuns you an operation which is about to be send to the ring when you call ring.wait,
that operation has operation.userdata and opration.userdata= functions which you can use however you like.
One example is turning a created tcp socket into a ruby TCPSocket object and storing that as the userdata for said operation.

```ruby
operation = ring.prep_socket(Socket::AF_INET, Socket::SOCK_STREAM, 0)
ring.wait do |operation|
    operation.userdata = operation.to_io
end
```

That way, you can do some socket operations which aren't implemented in this gem directly with the methods mruby gives you for a TCPSocket, any time you need it, like operation.userdata.remote_address to get the Addrinfo of the server you have connected to.
When using functions which swap out the operation you gave it the userdata is retained.

We check what type the underlaying socket is and give you a appropiate one back, be aware, you only gain TCPServer and UNIXServer objects back when the sockets are accepting connections, so you have to wait after you called prep_accept on them to gain the correct type.


LICENSE
=======
Copyright 2024, 2025 Hendrik Beskow

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this project except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
