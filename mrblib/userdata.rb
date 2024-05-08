class IO::Uring::UserData
  attr_reader :type, :socket, :buf, :res, :errno, :poll_mask
  attr_accessor :userdata
end
