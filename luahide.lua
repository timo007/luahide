#!/usr/bin/env lua5.3

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

local steg    = require("steg")
local ppm     = require("ppm")
local brotli  = require("brotli")
local base64  = require("base64")

local action  = nil   -- "e" for encode, "d" for decode.
local iimage  = nil   -- Cover image (encoding) or steganographic image (decoding).
local oimage  = nil   -- Steganographic image when encoding.
local mfile   = nil   -- File to read message from (encoding) or write to (decoding).
local verb    = false -- Verbose option.

action, iimage, oimage, mfile, verb = steg.cline(arg)

if action=="e" then
  --
  -- Burn a message (mfile) into a cover image (iimage), and write
  -- the output to the steganographic image (oimage). Use a 32 bit key (key)
  -- for generating pseudo-random numbers and encrypting the message.
  --

  -- Check if required files exist.
  if not steg.file_exists(iimage) then
    io.write("Error: Cover image, "..iimage..", does not exist\n")
    os.exit(1)
  end

  if not steg.file_exists(mfile) then
    io.write("Error: Message file, "..mfile..", does not exist\n")
    os.exit(1)
  end

  -- Get a password for encryption and pseudo-random number generation.
  local pwd = ""
  repeat
    pwd  = steg.getpwd("Enter an encryption pass phrase:")
    local pwd2  = steg.getpwd("Re-enter the pass phrase:")
    if pwd~=pwd2 then
      io.write("Passwords do not match - please try again.\n")
    end
  until pwd == pwd2

  -- Convert the cover image to PPM format and save it in a temporary file which
  -- is removed at the end.
  if verb then
    io.write("Converting "..iimage.." to PPM format\n")
  end
  
  local in_ppmfile = os.tmpname()
  local ctype = steg.imgtype(iimage)
  assert(os.execute("convert "..ctype..":"..iimage.." ppm:"..in_ppmfile))

  -- Read the cover image.
  if verb then
    io.write("Reading PPM data\n")
  end
  local cimg = ppm.readppm(in_ppmfile)
  
  -- Burn 96 random bits into the first 96 pixels. These are used as salt for
  -- the Argon2 hash and the chacha20 nonce.

  if verb then
    io.write("Burning random salt into the image\n")
  end
  local argon_salt = ""
  cimg, argon_salt = steg.addsalt(cimg)
  
  -- Generate the chacha20 key from the password and random salt.
  
  if verb then
    io.write("Generating Chacha-20 encryption key and nonces\n")
  end
  local key = steg.genkey(pwd, argon_salt)
  
  -- Create two nonces for use by chacha20. The first nonce is for use when
  -- generating pseudo-random numbers, the second is for use when encrypting.
  
  local prng_nonce = steg.incnonce(argon_salt)
  local enc_nonce  = steg.incnonce(prng_nonce)

  -- Shuffle the cover image pixels, starting with pixel 97 (after the salt which
  -- is in the first 96 pixels).
  if verb then
    io.write("Shuffling pixels in the image\n")
  end
  cimg = steg.shuffle(cimg, key, prng_nonce)

  -- Read the message.
  if verb then
    io.write("Reading message\n")
  end
  local msg = steg.readmsg(mfile)

  -- Compress the message using Brotli compression (which is meant to be good
  -- for text).
  
  local orig_len = string.len(msg)
  msg = brotli.compress(msg)
  local comp_len = string.len(msg)

  if verb then
    io.write("Brotli compression reduced message size from "..orig_len.." bytes to ".. 
      comp_len.." bytes \n") 
  end
  
  -- Encrypt the message.
  if verb then
    io.write("Encrypting message\n")
  end
  msg = steg.encrypt(key, enc_nonce, msg)

  -- Convert the message to bits.
  if verb then
    io.write("Converting message to bits\n")
  end
  local msgbits = steg.cvttobits(msg)

  -- Hide the message in the image after pixel 96.
  if verb then
    io.write("Burning in bits\n")
  end
  cimg = steg.addbits(cimg, 96, msgbits)

  -- Reorder the pixels in the cover image.
  if verb then
    io.write("Reordering image\n")
  end
  cimg = steg.reorder(cimg)

  -- Write the image back to a file.
  if verb then
    io.write("Writing image\n")
  end
  local out_ppmfile = os.tmpname()
  ppm.writeppm(cimg, out_ppmfile)

  assert(os.execute("convert PPM:"..out_ppmfile.." "..ctype..":"..oimage))
  
  -- Remove the temporary PPM files.
  os.remove(in_ppmfile)
  os.remove(out_ppmfile)

elseif action=="d" then
  -- Get the password.
  local pwd  = steg.getpwd("Enter the encryption pass phrase")

  print("Decoding image")
  -- Convert the stegonographic image to PPM format and save it in a temporary file
  -- which is removed at the end.
 
  local ppmfile = os.tmpname()
  local simgtype = steg.imgtype(iimage)
  assert(os.execute("convert "..simgtype..":"..iimage.." ppm:"..ppmfile))
  
  -- Read the steganographic image.
  local simg  = ppm.readppm(ppmfile)
  
  -- Get the salt from the LSB of the first 96 pixels.
  local argon_salt = steg.retrsalt(simg)
  
  -- Generate the chacha20 key
  local key = steg.genkey(pwd, argon_salt)
  print(base64.encode(argon_salt),pwd,base64.encode(key))
  
  -- Generate two nonces used for the chacha20 pseudo-random number generator
  -- and the encryption.
  local prng_nonce = steg.incnonce(argon_salt)
  local enc_nonce  = steg.incnonce(prng_nonce)

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
else
  print("No encoding or decoding action specified")
end
