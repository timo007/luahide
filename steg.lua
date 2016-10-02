-- Copyright (c) 2016 TIM HUME <tim@nomuka.com>
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-- WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-- MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
-- ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-- WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
-- ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
-- OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

local steg = {}

local chacha  = require("chacha")
local base64  = require("base64")
local argon2  = require("argon2")
local brotli  = require("brotli")
local ppm     = require("ppm")

function steg.cline(arg)
  -- Parse the command line arguments.
  
  local action=nil
  local iimage=nil
  local oimage=nil
  local mfile=nil
  local verb=false
  
  local idx=1
  while idx <= #arg do
    if arg[idx]=="-d" then
      action="d"
      idx = idx+1
    elseif arg[idx]=="-e" then
      action="e"
      idx = idx+1
    elseif arg[idx]=="-i" then
      iimage=arg[idx+1]
      idx = idx+2
    elseif arg[idx]=="-m" then
      mfile=arg[idx+1]
      idx = idx+2
    elseif arg[idx]=="-o" then
      oimage=arg[idx+1]
      idx = idx+2
    elseif arg[idx]=="-v" then
      verb=true
      idx = idx+1
    else
      print("Invalid argument: ",arg[idx])
      break
    end
  end
  
  return action,iimage, oimage, mfile, verb
end

function steg.getpwd(msg)
  -- Get a password without echoing it to the terminal.
  io.write(msg.."\n")
  io.flush()
  
  -- Get the current terminal settings.
  local out = assert(io.popen("stty -g", 'r'),"Cannot get terminal settings.")
  local termset = assert(out:read('*a'),"Cannot get terminal settings.")
  out:close()
  
  -- Turn off echoing.
  assert(os.execute("stty -echo"),"Cannot turn off terminal echo.")
  
  -- Read the password from stdin.
  local pwd = io.read()
  
  -- Restore the original terminal settings
  assert(os.execute("stty "..termset),"Cannot restore terminal settings.")

  return pwd
end

function steg.incnonce(nonce)
  -- Increment a nonce (represented as a string) by one.
  local noncepart = {}
  local pos = 1
  local idx = 1
  
  while pos <= string.len(nonce) do
    noncepart[idx],pos = string.unpack("<I6", nonce, pos)
    idx = idx + 1
  end

  local inc = 1
  for i=#noncepart,1,-1 do
    if inc == 1 then
      local incval = (noncepart[i]+1)%(2^48)
      if incval > noncepart[i] then
        inc = 0
      end
      noncepart[i] = incval
    end  
  end

  local incnonce = ""
  for i=1,#noncepart,1 do
    incnonce = incnonce..string.pack("<I6", noncepart[i])
  end
  
  return incnonce    
end

function steg.imgtype(infile)
  -- Use the Image Magick identify command to get the image type.
  local out = assert(io.popen("identify -format %[m] "..infile, 'r'))
  local imgtype = assert(out:read('*a'))
  out:close()
  
  return imgtype
  
end
  
function steg.readmsg(mfile)
  -- Read the message file into a string.
  
  local msgfile = io.open(mfile, "rb")
  local msg     = msgfile:read("a")
  msgfile:close()

  return msg
end

function steg.random(n)
    local urand = assert(io.open("/dev/urandom", "rb"))
    local randbytes = assert(urand:read(n))
    assert(urand:close())
    return randbytes
end

function steg.prng(nonce, key, n)
  -- Use the chacha stream cipher to generate pseudo-random unsigned
  -- eight bit integers.

  local rndstr  = chacha.ietf_crypt(20, key, nonce, string.rep("\0",n))

  return rndstr
end

function steg.encrypt(key, enc_nonce, msg)
  -- Use the chacha stream cipher to encrypt a message.

  local encmsg = enc_nonce..chacha.ietf_crypt(20, key, enc_nonce, msg)

  return encmsg
end

function steg.decrypt(key, enc_nonce, encmsg)
  -- Use the chacha stream cipher to encrypt a message.

  local msg = chacha.ietf_crypt(20, key, enc_nonce, string.sub(encmsg,13,-1))

  return msg
end
  
function steg.genkey(pwd, salt)
  -- Use argon2 to generate a 32 byte key.
  local hash = assert(argon2.encrypt(pwd, salt, {
    t_cost = 4,
    m_cost = 24,
    parallelism = 2
  }))

  local count=1
  local hashpart={}

  for part in string.gmatch(hash, "$([^$]+)") do
   hashpart[count] = part
   count = count + 1
  end

  local key = base64.decode(hashpart[5].."=")

  return key
end

function steg.cvttobits(msg)

  -- Prefix the message with the message length in bits.

  msg = string.pack("<I6", string.len(msg)*8)..msg

  -- Convert the message to bits.

  local pos       = 1
  local i         = 0
  local byteval   = 0
  local bitpos    = 0
  local bitvals   = {}
  for i=1,string.len(msg),1 do
    byteval,pos         = string.unpack("B", msg, pos)
    bitpos              = (i-1)*8
    bitvals[bitpos + 1] = byteval & 1
    bitvals[bitpos + 2] = (byteval & 2) >> 1
    bitvals[bitpos + 3] = (byteval & 4) >> 2
    bitvals[bitpos + 4] = (byteval & 8) >> 3
    bitvals[bitpos + 5] = (byteval & 16) >> 4
    bitvals[bitpos + 6] = (byteval & 32) >> 5
    bitvals[bitpos + 7] = (byteval & 64) >> 6
    bitvals[bitpos + 8] = (byteval & 128) >> 7
  end

  return bitvals
end

function steg.retrsalt(img)
  -- Get the salt from the first 96 pixels in the image.
  
  local salt  = ""
  local byteval = 0
  for i=1,96,1 do
    byteval = byteval | (img.pixval[i]&1)<<((i-1)%8)
    if i%8 == 0 then
      salt = salt..string.pack("B", byteval)
      byteval = 0
    end
  end
  
  return salt

end

function steg.retrieve_msg(img)

  -- Skip the first 96 pixels (which contained the salt).
  -- The next 48 pixels contain the message length.

  local lenstr  = ""
  local byteval = 0

  for i=97,144,1 do
    byteval  = byteval | (img.pixval[i]&1)<<((i-1)%8)
    if i%8 == 0 then
      lenstr = lenstr..string.pack("B", byteval)
      byteval = 0
    end
  end

  local msglen = string.unpack("<I6", lenstr)

  -- Get the remainder of the message.
  
  byteval = 0
  local msg     = ""

  for i=145,msglen+144,1 do
    byteval  = byteval | (img.pixval[i]&1)<<((i-1)%8)
    if i%8 == 0 then
      msg = msg..string.pack("B", byteval)
      byteval = 0
    end
  end

  return msg

end

function steg.addbits(img, startpix, msgbits)
  -- Need to:
  -- 2) Ensure we have more selected pixels than message bits.

  for i=1,#msgbits,1 do
    -- print(i, img.pixval[i], msgbits[i], (img.pixval[i]>>1<<1)|msgbits[i])
    img.pixval[i+startpix]  = (img.pixval[i+startpix]>>1<<1)|msgbits[i]    
  end

  return img
end

function steg.addsalt(img)
  -- Add 96 random bits for use as salt. These bits are burned into the first
  -- 96 pixels in the image.
  
  local salt = steg.random(12)
  local saltbits = table.move(steg.cvttobits(salt), 49, 144, 1, saltbits)
  
  for i=1,96,1 do
    img.pixval[i] = (img.pixval[i]>>1<<1)|saltbits[i]
  end
  
  return img, salt

end

function steg.reorder(img)
  -- Reorder the pixels in the cover image.
  local tmpval = {}
  local tmppos = {}
  table.move(img.pixval, 1, #img.pixval, 1, tmpval)
  table.move(img.pixpos, 1, #img.pixval, 1, tmppos)
  for i=1,#tmpval,1 do
    img.pixval[tmppos[i]] = tmpval[i]
    img.pixpos[tmppos[i]] = tmppos[i]
  end
  
  return img
end

function steg.shuffle(img, key, prng_nonce)
  -- Shuffle pixels 97- using the Fisher-Yates algorithm. Don't shuffle the first 96
  -- pixels, because these contain the salt.

  local rnd = steg.prng(prng_nonce, key, (#img.pixval-97)*6)

  local rndpos = 1
  local idx = 1
  for i=#img.pixval,98,-1 do
    --
    -- Generate a pseudo-random number between 97 and i
    --
    rndpos,idx = string.unpack("<I6", rnd, idx)
    rndpos     = rndpos%(i-96) + 97

    --
    -- Swap the current pixel with the randomly selected one.
    --

    img.pixval[i], img.pixval[rndpos] = img.pixval[rndpos], img.pixval[i]
    img.pixpos[i], img.pixpos[rndpos] = img.pixpos[rndpos], img.pixpos[i]
  end

  return img
end

return steg
