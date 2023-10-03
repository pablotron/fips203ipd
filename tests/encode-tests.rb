#!/usr/bin/env ruby
# frozen_string_literal: true

#
# generate encode tests for various bit widths
#

DS = [1, 4, 10] # bit lengths
Q = 3329 # modulus

# templates
T = {
  tests: %{
    // poly_encode_%<d>dbits() tests (0-3315, step=13)
    .name = "0-3315 (inc by 13)",
    .val = { .cs = { %<src>s } },
    .exp = { .cs = { %<dst>s } },
  }.rstrip,
}

# x -> round(2^d/Q * x)
def encode(x, d)
  Rational(2**d * x, Q).round
end

# x -> round(Q/2^d * x)
def decode(x, d)
  Rational(Q * x, 2**d).round
end

# print encode tests
puts(DS.map { |d|
  src = (0...Q).step(13).to_a[0, 256]
  dst = src.map { |x| decode(encode(x, d), d) % Q }
  T[:tests] % { d: d, src: src.join(', '), dst: dst.join(', ') }
}.join("\n\n"))
