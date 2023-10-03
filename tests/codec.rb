#!/usr/bin/env ruby
# frozen_string_literal: true

#
# generate encode/decode lookup tables for various bit widths
#

DS = [1, 4, 10] # bit lengths
Q = 3329 # modulus

# templates
T = {
  encode_lut: %{static const struct { uint16_t lo, hi; } ENCODE%<d>d_LUT[] = {\n%<rows>s\n};},
  encode_row: %{  { %<lo>d, %<hi>d }, // %<i>d},
  decode_lut: %{static const uint16_t DECODE%<d>d_LUT[] = {\n%<rows>s\n};},
  decode_row: %{  %<y>d, // %<x>d},
  tests: %{// poly_encode_%<d>dbits() tests (0-3315, step=13)\n.name = "0-3315 (inc by 13)",\n.val = { .cs = { %<src>s } }\n.exp = { .cs = { %<dst>s } },},
}

# x -> round(2^d/Q * x)
def encode(x, d)
  Rational(2**d * x, Q).round
end

# x -> round(Q/2^d * x)
def decode(x, d)
  Rational(Q * x, 2**d).round
end

# get encode LUT for given bit length
def encode_lut(d)
  lut = Q.times.each_with_object(Hash.new { |h, k| h[k] = [3329, 0] }) do |x, lut|
    y = encode(x, d)
    lut[y][0] = x if x < lut[y][0]
    lut[y][1] = x if x > lut[y][1]
  end

  T[:encode_lut] % {
    d: d,
    rows: lut.keys.sort.map { |i|
      T[:encode_row] % { i: i, lo: lut[i][0], hi: lut[i][1] }
    }.join("\n"),
  }
end

# get decode LUT for given bit length
def decode_lut(d)
  T[:decode_lut] % {
    d: d,
    rows: (2**d).times.map { |x|
      T[:decode_row] % { y: decode(x, d), x: x }
    }.join("\n"),
  }
end
  
# print LUTs for all bit lengths
puts(DS.map { |d|
  [encode_lut(d), decode_lut(d)].join("\n\n")
}.join("\n\n"))

# print encode tests
puts(DS.map { |d|
  src = (0...Q).step(13).to_a
  dst = src.map { |x| decode(encode(x, d), d) % Q }
  T[:tests] % { d: d, src: src.join(', '), dst: dst.join(', ') }
}.join("\n\n"))
