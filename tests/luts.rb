#!/usr/bin/env ruby

#
# luts.rb: generate NTT and BCM lookup tables.
#

B = 17
Q = 3329

def bitrev(n)
  ((n >> 6) & 1) |
    (((n >> 5) & 1) << 1) |
    (((n >> 4) & 1) << 2) |
    (((n >> 3) & 1) << 3) |
    (((n >> 2) & 1) << 4) |
    (((n >> 1) & 1) << 5) |
    (((n >> 0) & 1) << 6)
end

T = {
  main: %{
// number-theoretic transform (NTT) lookup table
static const uint16_t NTT_LUT[] = {
%<ntts>s
};

// polynomial base case multiply lookup table
static const uint16_t MUL_LUT[] = {
%<muls>s
};
},
  ntt: '  %<r>d, // n = %<n>d, bitrev(%<n>d) = %<e>d, (17**%<e>d)%%%<q>d = %<r>d',
  mul: '  %<r>d, // n = %<n>d, 2*bitrev(%<n>d)+1 = %<e>d, (17**%<e>d)%%%<q>d) = %<r>d',
}

puts(T[:main] % {
  ntts: 128.times.map { |n|
      T[:ntt] % {
      r: B.pow(bitrev(n), Q),
      q: Q,
      n: n,
      e: bitrev(n),
    }
  }.join("\n"),

  muls: 128.times.map { |n|
      T[:mul] % {
      r: B.pow(bitrev(n), Q),
      q: Q,
      n: n,
      e: 2 * bitrev(n) + 1,
    }
  }.join("\n"),
})
