require'std'
hpsock_info = {}
sessions = {}
for i = 0, 65535 do sessions[i] = {}; sessions[i].ip = 0; sessions[i].port = 0; sessions[i].pwd = "" end

hpsock = std:UdpSocket("*",6969)
hpsock_info.ip, hpsock_info.port = hpsock:getsockname()

print("socket listening on "..hpsock_info.ip..":"..hpsock_info.port)


local function is_registered(session_number,ip,port)
  for i,v in pairs(sessions) do
    if ip == v.ip and port == v.port then
      return true
    end
  end
  return false
end

local function request_password(split,ip,port,session_number)
  hpsock:sendto("PWD",ip,port)
  splitted = {}
  data = hpsock:receivefrom()
  if data:gsub("\n","") == sessions[tonumber(session_number)].pwd then
    return true
  else
    return false
  end
end

local function handler(split,ip,port)
  if split[1] == "setsession" or split[1] == "SETSESSION" and split[2] then
    -- register session --
    if split[2] == nil then -- i was sure `and split[2]` would do the trick but no
      return
    end
    if tonumber(split[2]) < 0 then
      print("host "..ip..":"..port.." tried to create a session on number under 0 ("..tonumber(split[2])..")")
      hpsock:sendto("OUTOFBOUNDS", ip, port)
      return
    elseif tonumber(split[2]) > 65535 then
      print("host "..ip..":"..port.." tried to create a session on number over 65535 ("..tonumber(split[2])..")")
      hpsock:sendto("OUTOFBOUNDS",ip, port)
      return
    end
    if sessions[tonumber(split[2])].ip == 0 and sessions[tonumber(split[2])].port == 0 then
      if is_registered(tonumber(split[2]),ip,port) then
        print("host "..ip..":"..port.." tried to register a session but already has one")
        hpsock:sendto("CLOSEFIRST",ip,port)
        return
      else
        sessions[tonumber(split[2])].ip = ip
        sessions[tonumber(split[2])].port = port
        print("host "..ip..":"..port.." registered a session on number "..split[2])
        hpsock:sendto("OK",ip,port)
        return
      end
    else
      print("host "..ip..":"..port.." tried registering a session on taken number "..split[2])
      hpsock:sendto("DENIED",ip,port)
      return
    end
  elseif split[1] == "getsession" or split[1] == "GETSESSION" and split[2] then
    -- send session, check if session has password and request password when set --
    if split[2] == nil then
      return
    end
    if sessions[tonumber(split[2])].ip == 0 or sessions[tonumber(split[2])].port == 0 or not sessions[tonumber(split[2])] or not sessions[tonumber(split[2])].ip or not sessions[tonumber(split[2])].port then
      print("host "..ip..":"..port.." has tried to request invalid session "..tonumber(split[2]))
      hpsock:sendto("DENIED",ip,port)
      return
    end
    if sessions[tonumber(split[2])].pwd == "" or not sessions[tonumber(split[2])] then
      for i,v in pairs(sessions[tonumber(split[2])]) do print(i,v) end
      hpsock:sendto("OK",ip,port)
      hpsock:sendto(tostring(sessions[tonumber(split[2])].ip), ip, port)
      hpsock:sendto(tostring(sessions[tonumber(split[2])].port), ip, port)
      print("host "..ip..":"..port.." has retrieved session "..tonumber(split[2]))
      return
    else
      local res = request_password(split,ip,port,tonumber(split[2]))
      if res == true then
        hpsock:sendto("OK",ip,port)
        hpsock:sendto(tostring(sessions[tonumber(split[2])].ip), ip, port)
        hpsock:sendto(tostring(sessions[tonumber(split[2])].port), ip, port)
        print("host "..ip..":"..port.." has successfully authenticated and retrieved session "..tonumber(split[2]))
        hpsock:sendto("OK",ip,port)
        return
      else
        print("host "..ip..":"..port.." has unsuccessfully tried to retrieve session "..tonumber(split[2]))
        hpsock:sendto("DENIED",ip,port)
        return
      end
    end
  elseif split[1] == "stopsession" or split[1] == "STOPSESSION" and split[2] then
    -- stop session, check if session has password and request password when set --
    if split[2] == nil then
      return
    end
    if ip == sessions[tonumber(split[2])].ip and port == sessions[tonumber(split[2])].port then
      sessions[tonumber(split[2])] = nil
      collectgarbage()
      print("host "..ip..":"..port.." has stopped session "..tonumber(split[2]))
      hpsock:sendto("OK",ip,port)
      return
    else
      print("host "..ip..":"..port.." tried to close session "..tonumber(split[2]).." without owning it")
      hpsock:sendto("DENIED",ip,port)
      return
    end
  elseif split[1] == "setpwd" or split[1] == "SETPWD" and split[2] and split[3] then
    if split[2] == nil then
      return
    end
    -- set password for session, check if session has password and reset to new one --
    if not sessions[tonumber(split[2])] or (not sessions[tonumber(split[2])].ip and not sessions[tonumber(split[2])].port) then
      print("host "..ip..":"..port.." tried to set a password for non-existant session "..tostring(split[2]))
      hpsock:sendto("DENIED",ip,port)
    end
    if ip == sessions[tonumber(split[2])].ip and port == sessions[tonumber(split[2])].port then
      sessions[tonumber(split[2])].pwd = string.gsub(tostring(split[3]),"\n","")
      print("host "..ip..":"..port.." has set a password for session "..tonumber(split[2]))
      hpsock:sendto("OK",ip,port)
      return
    else
      print("host "..ip..":"..port.." tried to set a password for session "..tonumber(split[2]).." but they do not own it")
      hpsock:sendto("DENIED",ip,port)
      return
    end
  end
end

function main()
  while true do
    split = {}
    local __splitter = function(tok) table.insert(split,tok) end

    data,ip,port = hpsock:receivefrom()
    string.tokensplit(data,__splitter)
    handler(split,ip,port)
  end
end

main()
