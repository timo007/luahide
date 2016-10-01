#!/usr/bin/env lua5.3

local steg  = require("steg")

--
-- Encode a message in a cover image.
--
print("Encoding image")
steg.encode("flower.png", "manifesto.txt", "steg.png", "password")

print("Decoding image")
steg.decode("steg.png", "decoded.txt", "password")
