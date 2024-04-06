# mruby-io_uring

io_uring for mruby (WIP)

Requirements
============
This requires at least Linux 5.6

Supported functions
===================

At the moment the following functions are implemented.
```c
io_uring_queue_init
io_uring_get_sqe
io_uring_submit
io_uring_prep_socket
io_uring_prep_accept
io_uring_prep_recv
io_uring_prep_splice
io_uring_prep_send
io_uring_prep_shutdown
io_uring_prep_close
io_uring_prep_poll_add
io_uring_wait_cqe_timeout
```

Here is an example on how to use them
-------------------------------------
```ruby
body = "hallo\n"
headers = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\n\r\n"
response = "#{headers}#{body}"
uring = IO::Uring.new
server = TCPServer.new(12345)
server.listen(4096)
uring.accept(server)

while true
  uring.wait do |userdata|
    raise userdata.errno if userdata.errno
    case userdata.type
    when :accept
      uring.recv(userdata.res).accept(server)
    when :recv
      uring.send(userdata.sock, response)
    when :send
      uring.close(userdata.sock)
    end
  end
end
```

uring.wait accepts a timeout as a float value, if a timeout occurs false is returned.

You can also use uring.wait without a block.
It returns an array which you can then iterate over.

Every instanced IO::Uring method accepts a sqe parameter as the last one, you can get a sqe by calling uring.sqe
```ruby
uring.send(response, 0, uring.sqe)
```

Benchmark
=========

Tested on Windows 11 inside a wsl 2 VM. Ryzen 7 5800x, 32gb DDR 3200 Ram.
```pre
hey -z 3s -cpus 6 http://127.0.0.1:12345

Summary:
  Total:        3.0009 secs
  Slowest:      0.0493 secs
  Fastest:      0.0000 secs
  Average:      0.0005 secs
  Requests/sec: 95773.6435

  Total data:   1724430 bytes
  Size/request: 6 bytes

Response time histogram:
  0.000 [1]     |
  0.005 [287204]        |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.010 [0]     |
  0.015 [0]     |
  0.020 [0]     |
  0.025 [0]     |
  0.030 [0]     |
  0.035 [0]     |
  0.039 [0]     |
  0.044 [24]    |
  0.049 [176]   |


Latency distribution:
  10% in 0.0003 secs
  25% in 0.0003 secs
  50% in 0.0004 secs
  75% in 0.0006 secs
  90% in 0.0008 secs
  95% in 0.0009 secs
  99% in 0.0015 secs

Details (average, fastest, slowest):
  DNS+dialup:   0.0000 secs, 0.0000 secs, 0.0493 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0000 secs, 0.0000 secs, 0.0019 secs
  resp wait:    0.0003 secs, 0.0000 secs, 0.0488 secs
  resp read:    0.0001 secs, 0.0000 secs, 0.0023 secs

Status code distribution:
  [200] 287405 responses
```