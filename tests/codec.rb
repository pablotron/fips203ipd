#!/usr/bin/env ruby
# frozen_string_literal: true

#
# generate encode/decode lookup tables for various bit sizes.
#
# - KEM512 use 1, 4, and 10
# - KEM768 use 1, 4, and 10
# - KEM1024 use 1, 5, and 11
#
# The output of this script is embedded in the top-level file
# `fips203.c`.
#

DS = [4, 10] # bit lengths (1 excluded)
Q = 3329 # modulus

# templates
T = {
  encode_lut: %{// Polynomial coefficient %<d>d-bit encoding lookup table\n// (used by `poly_encode_%<d>dbit()`)\nstatic const struct { uint16_t lo, hi; } ENCODE%<d>d_LUT[] = {\n%<rows>s\n};},
  encode_row: %{  { %<lo>d, %<hi>d }, // %<i>d},
  decode_lut: %{// polynomial coefficient %<d>d-bit decoding lookup table\n// (used by `poly_decode_%<d>dbit()`)\nstatic const uint16_t DECODE%<d>d_LUT[] = {\n%<rows>s\n};},
  decode_row: %{  %<y>d, // %<x>d},
}

# x -> round(2^d/Q * x)
def encode(x, d)
  Rational(2**d * x, Q).round
end

# x -> round(Q/2^d * x)
def decode(x, d)
  Rational(Q * x, 2**d).round
end

# get encode LUT for given bit length `d`
def encode_lut(d)
  lut = Q.times.each_with_object(Hash.new { |h, k| h[k] = [3329, 0] }) do |x, lut|
    y = encode(x, d)
    lut[y][0] = x if x < lut[y][0] # set new lower bound
    lut[y][1] = x if x > lut[y][1] # set new upper bound
  end

  T[:encode_lut] % {
    d: d,
    rows: lut.keys.sort.map { |i|
      T[:encode_row] % { i: i, lo: lut[i][0], hi: lut[i][1] }
    }.join("\n"),
  }
end

# get decode LUT for given bit length `d`
def decode_lut(d)
  T[:decode_lut] % {
    d: d,
    rows: (2**d).times.map { |x|
      T[:decode_row] % { y: decode(x, d), x: x }
    }.join("\n"),
  }
end

# print tables to stdout
puts DS.map { |d| encode_lut(d) }.join("\n\n"),
     '', # blank line to delimit encode/decode tables
     DS.map { |d| decode_lut(d) }.join("\n\n")
