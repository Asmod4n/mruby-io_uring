=begin
class IO::Uring
  attr_accessor :sendfile_chunks
  attr_reader :sendfile_socket

  def sendfile(sendfile_socket, filename)
    @sendfile_socket, @filename = sendfile_socket, filename
    @file = File.open(filename, 'r')
    @pipe_out, @pipe_in = IO.pipe
    @filesize = @file.size
    @sendfile_chunks = 0
    chunksize = 65536
    to_send = @filesize
    offset = 0
    while to_send > 0
      chunk = chunksize
      if chunk > @filesize - offset
        chunk = @filesize - offset
      end
      to_send -= chunk
      splice(@file, offset, @pipe_in, -1, chunk, 0, sqe.io_link)
      sq = sqe
      splice(@pipe_out, -1, @sendfile_socket,  -1, chunk, 0, sq)
      if to_send > 0
        sq.io_link
      end
      @sendfile_chunks += 1
    end
    self
  end

  def close_sendfile
    close @sendfile_socket
    @file.close
    @pipe_out.close
    @pipe_in.close
    remove_instance_variable :@sendfile_socket
    remove_instance_variable :@file
    remove_instance_variable :@pipe_out
    remove_instance_variable :@pipe_in
    remove_instance_variable :@filesize
    remove_instance_variable :@sendfile_chunks
    self
  end
end
=end
