local steg = {}

local chacha  = require("chacha")
local base64  = require("base64")
local argon2  = require("argon2")
local brotli  = require("brotli")
local ppm     = require("ppm")

function steg.encode(cfile, mfile, sfile, pwd)
  --
  -- Burn a message (mfile) into a cover image (cfile), and write
  -- the output to the steganographic image (sfile). Use a 32 bit key (key)
  -- for generating pseudo-random numbers and encrypting the message.
  --
  
  -- Convert the cover image to PPM format and save it in a temporary file which
  -- is removed at the end.
  local in_ppmfile = os.tmpname()
  local ctype = steg.imgtype(cfile)
  assert(os.execute("convert "..ctype..":"..cfile.." ppm:"..in_ppmfile))

  -- Read the cover image.
  local cimg = ppm.readppm(in_ppmfile)
  
  -- Burn 96 random bits into the first 96 pixels. These are used as salt for
  -- the Argon2 hash and the chacha20 nonce.

  local argon_salt = ""
  cimg, argon_salt = steg.addsalt(cimg)
  
  -- Generate the chacha20 key from the password and random salt.
  
  local key = steg.genkey(pwd, argon_salt)
  
  -- Create two nonces for use by chacha20. The first nonce is for use when
  -- generating pseudo-random numbers, the second is for use when encrypting.
  
  local prng_nonce = argon_salt -- Will change this.
  local enc_nonce  = argon_salt -- Will change this.

  -- Shuffle the cover image pixels, starting with pixel 97 (after the salt which
  -- is in the first 96 pixels).
  cimg = steg.shuffle(cimg, key, prng_nonce)

  -- Read and the message.
  local msg = steg.readmsg(mfile)

  -- Compress the message using Brotli compression (which is meant to be good
  -- for text).
  
  msg = brotli.compress(msg)
  
  -- Encrypt the message.
  msg = steg.encrypt(key, enc_nonce, msg)

  -- Convert the message to bits.
  print("Converting message to bits")
  local msgbits = steg.cvttobits(msg)

  -- Hide the message in the image after pixel 96.
  print("Burning in bits")
  cimg = steg.addbits(cimg, 96, msgbits)

  -- Reorder the pixels in the cover image.
  print("Reordering image")
  cimg = steg.reorder(cimg)

  -- Write the image back to a file.
  print("Writing image")
  local out_ppmfile = os.tmpname()
  ppm.writeppm(cimg, out_ppmfile)

  assert(os.execute("convert PPM:"..out_ppmfile.." "..ctype..":"..sfile))
  
  -- Remove the temporary PPM files.
  os.remove(in_ppmfile)
  os.remove(out_ppmfile)

end

function steg.decode(sfile, mfile, pwd)
  
  -- Convert the stegonographic image to PPM format and save it in a temporary file
  -- which is removed at the end.
 
  local ppmfile = os.tmpname()
  local simgtype = steg.imgtype(sfile)
  assert(os.execute("convert "..simgtype..":"..sfile.." ppm:"..ppmfile))
  
  -- Read the steganographic image.
  local simg  = ppm.readppm(ppmfile)
  
  -- Get the salt from the LSB of the first 96 pixels.
  local argon_salt = steg.retrsalt(simg)
  
  -- Generate the chacha20 key
  local key = steg.genkey(pwd, argon_salt)
  
  -- Generate two nonces used for the chacha20 pseudo-random number generator
  -- and the encryption.
  local prng_nonce = argon_salt
  local enc_nonce  = argon_salt

  -- Shuffle the selected pixels.
  simg = steg.shuffle(simg, key, prng_nonce)

  -- Extract and decrypt the message from the shuffled pixels.
  local msg = steg.retrieve_msg(simg)
  msg = steg.decrypt(key, enc_nonce, msg)
  msg = brotli.decompress(msg)

  -- Write the message to the file.
  print(msg)
  
  -- Remove the temporary PPM file
  os.remove(ppmfile)
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
  
function steg.genkey(password, salt)
  -- Use argon2 to generate a 32 byte key.
  local hash = assert(argon2.encrypt("password", "somesalt", {
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

  msg = string.pack("I6", string.len(msg)*8)..msg

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

  local msglen = string.unpack("I6", lenstr)

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
    rndpos,idx = string.unpack("I6", rnd, idx)
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