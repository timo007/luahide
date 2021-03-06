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

local ppm = {}

function ppm.readppm(filename)
   
    -- Read the whole PPM image file into a string.

    local ppmfile = io.open(filename, "rb")
    local ppmdata = ppmfile:read("a")
    ppmfile:close()

    -- A table to hold all the image header information and data

    local ppm = {
        magicnum    = "P6",     -- NetPBM magic number
        width       = 0,        -- Image width
        height      = 0,        -- Image height
        maxval      = 255,      -- Maximum R/G/B channel value
        rgb_format  = "B",      -- Format to parse RGB pixels
        pixpos      = {},       -- Position of each pixel
        pixval      = {},       -- The pixels as numbers
    }
    
    local rgb = ""

    -- Parse the PPM image.

    local ppm_pattern  = "(P%d)%s+(%d+)%s+(%d+)%s+(%d+)%s(.*)"

    ppm.magicnum, ppm.width, ppm.height, ppm.maxval, rgb
        = string.match(ppmdata, ppm_pattern)

    -- Convert the raw pixel values to numbers.

    if tonumber(ppm.maxval) <= 255 then
        ppm.rgb_format  = "B"
    else
        ppm.rgb_format  = "<I2"     -- Little endian
    end

    local pos = 1
    local i
    for i=1,tonumber(ppm.width)*tonumber(ppm.height)*3,1
    do  
        ppm.pixval[i],pos  = string.unpack(ppm.rgb_format, rgb, pos)
        ppm.pixpos[i]       = i
    end

    return ppm
end

function ppm.writeppm(ppm, filename)
    -- Open the file for writing.

    local ppmfile = io.open(filename, "wb")

    -- Write the PPM header.

    ppmfile:write(ppm.magicnum .. "\n")
    ppmfile:write(ppm.width .. " " .. ppm.height .. "\n")
    ppmfile:write(ppm.maxval .. "\n")

    -- Pack the pixels and write to the file.

    local i
    for i=1,tonumber(ppm.width)*tonumber(ppm.height)*3,1
    do  
        ppmfile:write(string.pack(ppm.rgb_format, ppm.pixval[i]))
    end

    ppmfile:close()
end

return ppm
