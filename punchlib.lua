--local errors = {
--  invalid_session = "SESSIONINVALID",
--  out_of_bounds = "OUTOFBOUNDS",
--  denied = "DENIED",
--  invalid_request = "INVALIDREQUEST",
--  close_first = "CLOSEFIRST",
--}


function PunchGet(socket,session_number,hpip,hpport,pwd)
    assert(socket:sendto("GETSESSION "..tostring(session_number),hpip,hpport))
    local res = socket:receivefrom()
    if res == "PWD" then
      if pwd then
        socket:sendto(pwd,hpip,hpport)
        res = socket:receivefrom()
        if res ~= "OK" then
          error("incorrect password specified")
        else
          ip = socket:receivefrom()
          port = socket:receivefrom()
          return ip,port
        end
      else
        error("tried to retrieve password-protected session but no password specified")
      end
    elseif res == "OK" then
      ip = socket:receivefrom()
      port = socket:receivefrom()
      if ip and port then return ip,port end
    end
end

function PunchSet(socket,session_number,hpip,hpport)
  assert(socket:sendto("SETSESSION "..tostring(session_number),hpip,hpport))
  local res = socket:receivefrom()
  if res == "OK" then
    return
  elseif res == "CLOSEFIRST" then
    error("your application tried to register a session whilst having an existing session")
  elseif res == "OUTOFBOUNDS" then
    error("your session number exceeded 65535")
  else
    error("server responded with '"..res.."' trying to register on session number "..tostring(session_number))
  end
end

function PunchSetPwd(socket,session_number,hpip,hpport,pwd)
  assert(socket:sendto("SETPWD "..session_number.." "..pwd,hpip,hpport))
  local res = socket:receivefrom()
  if res == "OK" then
    return
  else
    error("server responded with '"..tostring(res).."' trying to register a password on session number "..tostring(session_number))
  end
end

function PunchClose(socket,session_number,hpip,hpport)
  assert(socket:sendto("STOPSESSION "..tostring(session_number),hpip,hpport))
  if res == "OK" then
    return
  elseif res == "DENIED" then
    error("your application tried to close a session you do not own")
  end
end
