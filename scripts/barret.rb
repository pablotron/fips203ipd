#!/usr/bin/env ruby

#
# test barret reduction 
# ref: https://en.wikipedia.org/wiki/Barrett_reduction
#

#
# calculate (a * b) % n with only mul, sub, shift, and mask
#
def barret(a, b, n, e)
  m = (1 << e)/n # pre-compute multiplier
  c = a * b # calculate product
  r = c - ((c * m) >> e) * n # barret reduction
  mask = (r < n) ? 0 : 0xfffff # calculate mask
  r - (n & mask) # post-reduction adjustment
end

def test_barret
  # number of random tests
  num_rand_tests = 5_000_000

  # fixed tests
  tests = [
    # a, b: operands, n: modulus, e: exponent
    { a: 5, b: 6, n: 7, e: 3 },
    { a: 5, b: 6, n: 7, e: 16 },
    { a: 5, b: 6, n: 7, e: 15 },
    { a: 5, b: 6, n: 7, e: 14 },
    { a: 5, b: 6, n: 7, e: 3 },
    { a: 5, b: 6, n: 7, e: 4 },
    { a: 3, b: 7, n: 13, e: 2 },
    { a: 3, b: 7, n: 13, e: 4 },
    { a: 4, b: 7, n: 13, e: 4 },
    { a: 12, b: 7, n: 13, e: 4 },
  ]

  # run fixed tests
  puts 'running fixed tests'
  tests.each do |t|
    exp = (t[:a] * t[:b]) % t[:n] # get expected value
    got = barret(t[:a], t[:b], t[:n], t[:e])
    raise "test failed: t = #{t}: got #{got}, exp #{exp}" if got != exp
  end

  # run 1000 random tests
  puts "running #{num_rand_tests} random tests"
  num_rand_tests.times.each do
    # generate test (a, b: operands, n: modulus, e: exponent)
    t = { a: rand(1<<12), b: rand(1<<12), n: 65537, e: 24 }
    exp = (t[:a] * t[:b]) % t[:n] # get expected value
    got = barret(t[:a], t[:b], t[:n], t[:e])
    raise "test failed: t = #{t}: got #{got}, exp #{exp}" if got != exp
  end

  puts 'ok'
end

test_barret

