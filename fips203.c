#include <stdbool.h> // bool
#include <stddef.h> // size_t
#include <stdint.h> // uint8_t
#include <string.h> // memcpy()
#include "sha3.h" // sha3
#include "fips203.h"

#define Q 3329

#define PKE512_K 2
#define PKE512_ETA1 3
#define PKE512_ETA2 2
#define PKE512_DU 10
#define PKE512_DV 4
#define PKE512_EK_SIZE (384 * PKE512_K + 32)
#define PKE512_DK_SIZE (384 * PKE512_K)
#define PKE512_CT_SIZE (32 * (PKE512_DU * PKE512_K + PKE512_DV))

#define FIPS203_KEM768 3
#define FIPS203_KEM768_ETA1 2
#define FIPS203_KEM768_ETA2 2
#define FIPS203_KEM768_DU 10
#define FIPS203_KEM768_DV 4

#define FIPS203_KEM1024 4
#define FIPS203_KEM1024_ETA1 2
#define FIPS203_KEM1024_ETA2 2
#define FIPS203_KEM1024_DU 11
#define FIPS203_KEM1024_DV 5

// number-theoretic transform (NTT) lookup table
// (used by poly_ntt() and poly_inv_ntt())
static const uint16_t NTT_LUT[] = {
  1, // n = 0, bitrev(0) = 0, (17**0)%3329 = 1
  1729, // n = 1, bitrev(1) = 64, (17**64)%3329 = 1729
  2580, // n = 2, bitrev(2) = 32, (17**32)%3329 = 2580
  3289, // n = 3, bitrev(3) = 96, (17**96)%3329 = 3289
  2642, // n = 4, bitrev(4) = 16, (17**16)%3329 = 2642
  630, // n = 5, bitrev(5) = 80, (17**80)%3329 = 630
  1897, // n = 6, bitrev(6) = 48, (17**48)%3329 = 1897
  848, // n = 7, bitrev(7) = 112, (17**112)%3329 = 848
  1062, // n = 8, bitrev(8) = 8, (17**8)%3329 = 1062
  1919, // n = 9, bitrev(9) = 72, (17**72)%3329 = 1919
  193, // n = 10, bitrev(10) = 40, (17**40)%3329 = 193
  797, // n = 11, bitrev(11) = 104, (17**104)%3329 = 797
  2786, // n = 12, bitrev(12) = 24, (17**24)%3329 = 2786
  3260, // n = 13, bitrev(13) = 88, (17**88)%3329 = 3260
  569, // n = 14, bitrev(14) = 56, (17**56)%3329 = 569
  1746, // n = 15, bitrev(15) = 120, (17**120)%3329 = 1746
  296, // n = 16, bitrev(16) = 4, (17**4)%3329 = 296
  2447, // n = 17, bitrev(17) = 68, (17**68)%3329 = 2447
  1339, // n = 18, bitrev(18) = 36, (17**36)%3329 = 1339
  1476, // n = 19, bitrev(19) = 100, (17**100)%3329 = 1476
  3046, // n = 20, bitrev(20) = 20, (17**20)%3329 = 3046
  56, // n = 21, bitrev(21) = 84, (17**84)%3329 = 56
  2240, // n = 22, bitrev(22) = 52, (17**52)%3329 = 2240
  1333, // n = 23, bitrev(23) = 116, (17**116)%3329 = 1333
  1426, // n = 24, bitrev(24) = 12, (17**12)%3329 = 1426
  2094, // n = 25, bitrev(25) = 76, (17**76)%3329 = 2094
  535, // n = 26, bitrev(26) = 44, (17**44)%3329 = 535
  2882, // n = 27, bitrev(27) = 108, (17**108)%3329 = 2882
  2393, // n = 28, bitrev(28) = 28, (17**28)%3329 = 2393
  2879, // n = 29, bitrev(29) = 92, (17**92)%3329 = 2879
  1974, // n = 30, bitrev(30) = 60, (17**60)%3329 = 1974
  821, // n = 31, bitrev(31) = 124, (17**124)%3329 = 821
  289, // n = 32, bitrev(32) = 2, (17**2)%3329 = 289
  331, // n = 33, bitrev(33) = 66, (17**66)%3329 = 331
  3253, // n = 34, bitrev(34) = 34, (17**34)%3329 = 3253
  1756, // n = 35, bitrev(35) = 98, (17**98)%3329 = 1756
  1197, // n = 36, bitrev(36) = 18, (17**18)%3329 = 1197
  2304, // n = 37, bitrev(37) = 82, (17**82)%3329 = 2304
  2277, // n = 38, bitrev(38) = 50, (17**50)%3329 = 2277
  2055, // n = 39, bitrev(39) = 114, (17**114)%3329 = 2055
  650, // n = 40, bitrev(40) = 10, (17**10)%3329 = 650
  1977, // n = 41, bitrev(41) = 74, (17**74)%3329 = 1977
  2513, // n = 42, bitrev(42) = 42, (17**42)%3329 = 2513
  632, // n = 43, bitrev(43) = 106, (17**106)%3329 = 632
  2865, // n = 44, bitrev(44) = 26, (17**26)%3329 = 2865
  33, // n = 45, bitrev(45) = 90, (17**90)%3329 = 33
  1320, // n = 46, bitrev(46) = 58, (17**58)%3329 = 1320
  1915, // n = 47, bitrev(47) = 122, (17**122)%3329 = 1915
  2319, // n = 48, bitrev(48) = 6, (17**6)%3329 = 2319
  1435, // n = 49, bitrev(49) = 70, (17**70)%3329 = 1435
  807, // n = 50, bitrev(50) = 38, (17**38)%3329 = 807
  452, // n = 51, bitrev(51) = 102, (17**102)%3329 = 452
  1438, // n = 52, bitrev(52) = 22, (17**22)%3329 = 1438
  2868, // n = 53, bitrev(53) = 86, (17**86)%3329 = 2868
  1534, // n = 54, bitrev(54) = 54, (17**54)%3329 = 1534
  2402, // n = 55, bitrev(55) = 118, (17**118)%3329 = 2402
  2647, // n = 56, bitrev(56) = 14, (17**14)%3329 = 2647
  2617, // n = 57, bitrev(57) = 78, (17**78)%3329 = 2617
  1481, // n = 58, bitrev(58) = 46, (17**46)%3329 = 1481
  648, // n = 59, bitrev(59) = 110, (17**110)%3329 = 648
  2474, // n = 60, bitrev(60) = 30, (17**30)%3329 = 2474
  3110, // n = 61, bitrev(61) = 94, (17**94)%3329 = 3110
  1227, // n = 62, bitrev(62) = 62, (17**62)%3329 = 1227
  910, // n = 63, bitrev(63) = 126, (17**126)%3329 = 910
  17, // n = 64, bitrev(64) = 1, (17**1)%3329 = 17
  2761, // n = 65, bitrev(65) = 65, (17**65)%3329 = 2761
  583, // n = 66, bitrev(66) = 33, (17**33)%3329 = 583
  2649, // n = 67, bitrev(67) = 97, (17**97)%3329 = 2649
  1637, // n = 68, bitrev(68) = 17, (17**17)%3329 = 1637
  723, // n = 69, bitrev(69) = 81, (17**81)%3329 = 723
  2288, // n = 70, bitrev(70) = 49, (17**49)%3329 = 2288
  1100, // n = 71, bitrev(71) = 113, (17**113)%3329 = 1100
  1409, // n = 72, bitrev(72) = 9, (17**9)%3329 = 1409
  2662, // n = 73, bitrev(73) = 73, (17**73)%3329 = 2662
  3281, // n = 74, bitrev(74) = 41, (17**41)%3329 = 3281
  233, // n = 75, bitrev(75) = 105, (17**105)%3329 = 233
  756, // n = 76, bitrev(76) = 25, (17**25)%3329 = 756
  2156, // n = 77, bitrev(77) = 89, (17**89)%3329 = 2156
  3015, // n = 78, bitrev(78) = 57, (17**57)%3329 = 3015
  3050, // n = 79, bitrev(79) = 121, (17**121)%3329 = 3050
  1703, // n = 80, bitrev(80) = 5, (17**5)%3329 = 1703
  1651, // n = 81, bitrev(81) = 69, (17**69)%3329 = 1651
  2789, // n = 82, bitrev(82) = 37, (17**37)%3329 = 2789
  1789, // n = 83, bitrev(83) = 101, (17**101)%3329 = 1789
  1847, // n = 84, bitrev(84) = 21, (17**21)%3329 = 1847
  952, // n = 85, bitrev(85) = 85, (17**85)%3329 = 952
  1461, // n = 86, bitrev(86) = 53, (17**53)%3329 = 1461
  2687, // n = 87, bitrev(87) = 117, (17**117)%3329 = 2687
  939, // n = 88, bitrev(88) = 13, (17**13)%3329 = 939
  2308, // n = 89, bitrev(89) = 77, (17**77)%3329 = 2308
  2437, // n = 90, bitrev(90) = 45, (17**45)%3329 = 2437
  2388, // n = 91, bitrev(91) = 109, (17**109)%3329 = 2388
  733, // n = 92, bitrev(92) = 29, (17**29)%3329 = 733
  2337, // n = 93, bitrev(93) = 93, (17**93)%3329 = 2337
  268, // n = 94, bitrev(94) = 61, (17**61)%3329 = 268
  641, // n = 95, bitrev(95) = 125, (17**125)%3329 = 641
  1584, // n = 96, bitrev(96) = 3, (17**3)%3329 = 1584
  2298, // n = 97, bitrev(97) = 67, (17**67)%3329 = 2298
  2037, // n = 98, bitrev(98) = 35, (17**35)%3329 = 2037
  3220, // n = 99, bitrev(99) = 99, (17**99)%3329 = 3220
  375, // n = 100, bitrev(100) = 19, (17**19)%3329 = 375
  2549, // n = 101, bitrev(101) = 83, (17**83)%3329 = 2549
  2090, // n = 102, bitrev(102) = 51, (17**51)%3329 = 2090
  1645, // n = 103, bitrev(103) = 115, (17**115)%3329 = 1645
  1063, // n = 104, bitrev(104) = 11, (17**11)%3329 = 1063
  319, // n = 105, bitrev(105) = 75, (17**75)%3329 = 319
  2773, // n = 106, bitrev(106) = 43, (17**43)%3329 = 2773
  757, // n = 107, bitrev(107) = 107, (17**107)%3329 = 757
  2099, // n = 108, bitrev(108) = 27, (17**27)%3329 = 2099
  561, // n = 109, bitrev(109) = 91, (17**91)%3329 = 561
  2466, // n = 110, bitrev(110) = 59, (17**59)%3329 = 2466
  2594, // n = 111, bitrev(111) = 123, (17**123)%3329 = 2594
  2804, // n = 112, bitrev(112) = 7, (17**7)%3329 = 2804
  1092, // n = 113, bitrev(113) = 71, (17**71)%3329 = 1092
  403, // n = 114, bitrev(114) = 39, (17**39)%3329 = 403
  1026, // n = 115, bitrev(115) = 103, (17**103)%3329 = 1026
  1143, // n = 116, bitrev(116) = 23, (17**23)%3329 = 1143
  2150, // n = 117, bitrev(117) = 87, (17**87)%3329 = 2150
  2775, // n = 118, bitrev(118) = 55, (17**55)%3329 = 2775
  886, // n = 119, bitrev(119) = 119, (17**119)%3329 = 886
  1722, // n = 120, bitrev(120) = 15, (17**15)%3329 = 1722
  1212, // n = 121, bitrev(121) = 79, (17**79)%3329 = 1212
  1874, // n = 122, bitrev(122) = 47, (17**47)%3329 = 1874
  1029, // n = 123, bitrev(123) = 111, (17**111)%3329 = 1029
  2110, // n = 124, bitrev(124) = 31, (17**31)%3329 = 2110
  2935, // n = 125, bitrev(125) = 95, (17**95)%3329 = 2935
  885, // n = 126, bitrev(126) = 63, (17**63)%3329 = 885
  2154, // n = 127, bitrev(127) = 127, (17**127)%3329 = 2154
};

// polynomial base case multiply lookup table
// (used by poly_mul())
static const uint16_t MUL_LUT[] = {
  17, // n = 0, 2*bitrev(0)+1 = 1, (17**1)%3329) = 17
  3312, // n = 1, 2*bitrev(1)+1 = 129, (17**129)%3329) = 3312
  2761, // n = 2, 2*bitrev(2)+1 = 65, (17**65)%3329) = 2761
  568, // n = 3, 2*bitrev(3)+1 = 193, (17**193)%3329) = 568
  583, // n = 4, 2*bitrev(4)+1 = 33, (17**33)%3329) = 583
  2746, // n = 5, 2*bitrev(5)+1 = 161, (17**161)%3329) = 2746
  2649, // n = 6, 2*bitrev(6)+1 = 97, (17**97)%3329) = 2649
  680, // n = 7, 2*bitrev(7)+1 = 225, (17**225)%3329) = 680
  1637, // n = 8, 2*bitrev(8)+1 = 17, (17**17)%3329) = 1637
  1692, // n = 9, 2*bitrev(9)+1 = 145, (17**145)%3329) = 1692
  723, // n = 10, 2*bitrev(10)+1 = 81, (17**81)%3329) = 723
  2606, // n = 11, 2*bitrev(11)+1 = 209, (17**209)%3329) = 2606
  2288, // n = 12, 2*bitrev(12)+1 = 49, (17**49)%3329) = 2288
  1041, // n = 13, 2*bitrev(13)+1 = 177, (17**177)%3329) = 1041
  1100, // n = 14, 2*bitrev(14)+1 = 113, (17**113)%3329) = 1100
  2229, // n = 15, 2*bitrev(15)+1 = 241, (17**241)%3329) = 2229
  1409, // n = 16, 2*bitrev(16)+1 = 9, (17**9)%3329) = 1409
  1920, // n = 17, 2*bitrev(17)+1 = 137, (17**137)%3329) = 1920
  2662, // n = 18, 2*bitrev(18)+1 = 73, (17**73)%3329) = 2662
  667, // n = 19, 2*bitrev(19)+1 = 201, (17**201)%3329) = 667
  3281, // n = 20, 2*bitrev(20)+1 = 41, (17**41)%3329) = 3281
  48, // n = 21, 2*bitrev(21)+1 = 169, (17**169)%3329) = 48
  233, // n = 22, 2*bitrev(22)+1 = 105, (17**105)%3329) = 233
  3096, // n = 23, 2*bitrev(23)+1 = 233, (17**233)%3329) = 3096
  756, // n = 24, 2*bitrev(24)+1 = 25, (17**25)%3329) = 756
  2573, // n = 25, 2*bitrev(25)+1 = 153, (17**153)%3329) = 2573
  2156, // n = 26, 2*bitrev(26)+1 = 89, (17**89)%3329) = 2156
  1173, // n = 27, 2*bitrev(27)+1 = 217, (17**217)%3329) = 1173
  3015, // n = 28, 2*bitrev(28)+1 = 57, (17**57)%3329) = 3015
  314, // n = 29, 2*bitrev(29)+1 = 185, (17**185)%3329) = 314
  3050, // n = 30, 2*bitrev(30)+1 = 121, (17**121)%3329) = 3050
  279, // n = 31, 2*bitrev(31)+1 = 249, (17**249)%3329) = 279
  1703, // n = 32, 2*bitrev(32)+1 = 5, (17**5)%3329) = 1703
  1626, // n = 33, 2*bitrev(33)+1 = 133, (17**133)%3329) = 1626
  1651, // n = 34, 2*bitrev(34)+1 = 69, (17**69)%3329) = 1651
  1678, // n = 35, 2*bitrev(35)+1 = 197, (17**197)%3329) = 1678
  2789, // n = 36, 2*bitrev(36)+1 = 37, (17**37)%3329) = 2789
  540, // n = 37, 2*bitrev(37)+1 = 165, (17**165)%3329) = 540
  1789, // n = 38, 2*bitrev(38)+1 = 101, (17**101)%3329) = 1789
  1540, // n = 39, 2*bitrev(39)+1 = 229, (17**229)%3329) = 1540
  1847, // n = 40, 2*bitrev(40)+1 = 21, (17**21)%3329) = 1847
  1482, // n = 41, 2*bitrev(41)+1 = 149, (17**149)%3329) = 1482
  952, // n = 42, 2*bitrev(42)+1 = 85, (17**85)%3329) = 952
  2377, // n = 43, 2*bitrev(43)+1 = 213, (17**213)%3329) = 2377
  1461, // n = 44, 2*bitrev(44)+1 = 53, (17**53)%3329) = 1461
  1868, // n = 45, 2*bitrev(45)+1 = 181, (17**181)%3329) = 1868
  2687, // n = 46, 2*bitrev(46)+1 = 117, (17**117)%3329) = 2687
  642, // n = 47, 2*bitrev(47)+1 = 245, (17**245)%3329) = 642
  939, // n = 48, 2*bitrev(48)+1 = 13, (17**13)%3329) = 939
  2390, // n = 49, 2*bitrev(49)+1 = 141, (17**141)%3329) = 2390
  2308, // n = 50, 2*bitrev(50)+1 = 77, (17**77)%3329) = 2308
  1021, // n = 51, 2*bitrev(51)+1 = 205, (17**205)%3329) = 1021
  2437, // n = 52, 2*bitrev(52)+1 = 45, (17**45)%3329) = 2437
  892, // n = 53, 2*bitrev(53)+1 = 173, (17**173)%3329) = 892
  2388, // n = 54, 2*bitrev(54)+1 = 109, (17**109)%3329) = 2388
  941, // n = 55, 2*bitrev(55)+1 = 237, (17**237)%3329) = 941
  733, // n = 56, 2*bitrev(56)+1 = 29, (17**29)%3329) = 733
  2596, // n = 57, 2*bitrev(57)+1 = 157, (17**157)%3329) = 2596
  2337, // n = 58, 2*bitrev(58)+1 = 93, (17**93)%3329) = 2337
  992, // n = 59, 2*bitrev(59)+1 = 221, (17**221)%3329) = 992
  268, // n = 60, 2*bitrev(60)+1 = 61, (17**61)%3329) = 268
  3061, // n = 61, 2*bitrev(61)+1 = 189, (17**189)%3329) = 3061
  641, // n = 62, 2*bitrev(62)+1 = 125, (17**125)%3329) = 641
  2688, // n = 63, 2*bitrev(63)+1 = 253, (17**253)%3329) = 2688
  1584, // n = 64, 2*bitrev(64)+1 = 3, (17**3)%3329) = 1584
  1745, // n = 65, 2*bitrev(65)+1 = 131, (17**131)%3329) = 1745
  2298, // n = 66, 2*bitrev(66)+1 = 67, (17**67)%3329) = 2298
  1031, // n = 67, 2*bitrev(67)+1 = 195, (17**195)%3329) = 1031
  2037, // n = 68, 2*bitrev(68)+1 = 35, (17**35)%3329) = 2037
  1292, // n = 69, 2*bitrev(69)+1 = 163, (17**163)%3329) = 1292
  3220, // n = 70, 2*bitrev(70)+1 = 99, (17**99)%3329) = 3220
  109, // n = 71, 2*bitrev(71)+1 = 227, (17**227)%3329) = 109
  375, // n = 72, 2*bitrev(72)+1 = 19, (17**19)%3329) = 375
  2954, // n = 73, 2*bitrev(73)+1 = 147, (17**147)%3329) = 2954
  2549, // n = 74, 2*bitrev(74)+1 = 83, (17**83)%3329) = 2549
  780, // n = 75, 2*bitrev(75)+1 = 211, (17**211)%3329) = 780
  2090, // n = 76, 2*bitrev(76)+1 = 51, (17**51)%3329) = 2090
  1239, // n = 77, 2*bitrev(77)+1 = 179, (17**179)%3329) = 1239
  1645, // n = 78, 2*bitrev(78)+1 = 115, (17**115)%3329) = 1645
  1684, // n = 79, 2*bitrev(79)+1 = 243, (17**243)%3329) = 1684
  1063, // n = 80, 2*bitrev(80)+1 = 11, (17**11)%3329) = 1063
  2266, // n = 81, 2*bitrev(81)+1 = 139, (17**139)%3329) = 2266
  319, // n = 82, 2*bitrev(82)+1 = 75, (17**75)%3329) = 319
  3010, // n = 83, 2*bitrev(83)+1 = 203, (17**203)%3329) = 3010
  2773, // n = 84, 2*bitrev(84)+1 = 43, (17**43)%3329) = 2773
  556, // n = 85, 2*bitrev(85)+1 = 171, (17**171)%3329) = 556
  757, // n = 86, 2*bitrev(86)+1 = 107, (17**107)%3329) = 757
  2572, // n = 87, 2*bitrev(87)+1 = 235, (17**235)%3329) = 2572
  2099, // n = 88, 2*bitrev(88)+1 = 27, (17**27)%3329) = 2099
  1230, // n = 89, 2*bitrev(89)+1 = 155, (17**155)%3329) = 1230
  561, // n = 90, 2*bitrev(90)+1 = 91, (17**91)%3329) = 561
  2768, // n = 91, 2*bitrev(91)+1 = 219, (17**219)%3329) = 2768
  2466, // n = 92, 2*bitrev(92)+1 = 59, (17**59)%3329) = 2466
  863, // n = 93, 2*bitrev(93)+1 = 187, (17**187)%3329) = 863
  2594, // n = 94, 2*bitrev(94)+1 = 123, (17**123)%3329) = 2594
  735, // n = 95, 2*bitrev(95)+1 = 251, (17**251)%3329) = 735
  2804, // n = 96, 2*bitrev(96)+1 = 7, (17**7)%3329) = 2804
  525, // n = 97, 2*bitrev(97)+1 = 135, (17**135)%3329) = 525
  1092, // n = 98, 2*bitrev(98)+1 = 71, (17**71)%3329) = 1092
  2237, // n = 99, 2*bitrev(99)+1 = 199, (17**199)%3329) = 2237
  403, // n = 100, 2*bitrev(100)+1 = 39, (17**39)%3329) = 403
  2926, // n = 101, 2*bitrev(101)+1 = 167, (17**167)%3329) = 2926
  1026, // n = 102, 2*bitrev(102)+1 = 103, (17**103)%3329) = 1026
  2303, // n = 103, 2*bitrev(103)+1 = 231, (17**231)%3329) = 2303
  1143, // n = 104, 2*bitrev(104)+1 = 23, (17**23)%3329) = 1143
  2186, // n = 105, 2*bitrev(105)+1 = 151, (17**151)%3329) = 2186
  2150, // n = 106, 2*bitrev(106)+1 = 87, (17**87)%3329) = 2150
  1179, // n = 107, 2*bitrev(107)+1 = 215, (17**215)%3329) = 1179
  2775, // n = 108, 2*bitrev(108)+1 = 55, (17**55)%3329) = 2775
  554, // n = 109, 2*bitrev(109)+1 = 183, (17**183)%3329) = 554
  886, // n = 110, 2*bitrev(110)+1 = 119, (17**119)%3329) = 886
  2443, // n = 111, 2*bitrev(111)+1 = 247, (17**247)%3329) = 2443
  1722, // n = 112, 2*bitrev(112)+1 = 15, (17**15)%3329) = 1722
  1607, // n = 113, 2*bitrev(113)+1 = 143, (17**143)%3329) = 1607
  1212, // n = 114, 2*bitrev(114)+1 = 79, (17**79)%3329) = 1212
  2117, // n = 115, 2*bitrev(115)+1 = 207, (17**207)%3329) = 2117
  1874, // n = 116, 2*bitrev(116)+1 = 47, (17**47)%3329) = 1874
  1455, // n = 117, 2*bitrev(117)+1 = 175, (17**175)%3329) = 1455
  1029, // n = 118, 2*bitrev(118)+1 = 111, (17**111)%3329) = 1029
  2300, // n = 119, 2*bitrev(119)+1 = 239, (17**239)%3329) = 2300
  2110, // n = 120, 2*bitrev(120)+1 = 31, (17**31)%3329) = 2110
  1219, // n = 121, 2*bitrev(121)+1 = 159, (17**159)%3329) = 1219
  2935, // n = 122, 2*bitrev(122)+1 = 95, (17**95)%3329) = 2935
  394, // n = 123, 2*bitrev(123)+1 = 223, (17**223)%3329) = 394
  885, // n = 124, 2*bitrev(124)+1 = 63, (17**63)%3329) = 885
  2444, // n = 125, 2*bitrev(125)+1 = 191, (17**191)%3329) = 2444
  2154, // n = 126, 2*bitrev(126)+1 = 127, (17**127)%3329) = 2154
  1175, // n = 127, 2*bitrev(127)+1 = 255, (17**255)%3329) = 1175
};

// Polynomial with 256 coefficients.
typedef struct {
  uint16_t cs[256]; // coefficients
} poly_t;

// Initialize SHAKE128 XOF by absorbing 32 byte seed `r` followed by
// bytes `i` and `j`.
static inline void xof_init(sha3_xof_t * const xof, const uint8_t r[static 32], const uint8_t i, const uint8_t j) {
  // init shake128 xof
  shake128_xof_init(xof);

  // absorb rho
  shake128_xof_absorb(xof, r, 32);

  // absorb i and j
  const uint8_t ij[2] = { i, j };
  shake128_xof_absorb(xof, ij, 2);
}

// initialize polynomial by sampling from given xof.
static inline void poly_sample_ntt(poly_t * const a, const uint8_t rho[static 32], const uint8_t i, const uint8_t j) {
  // init xof by absorbing rho, i, and j
  sha3_xof_t xof = { 0 };
  xof_init(&xof, rho, i, j);

  for (size_t i = 0; i < 256;) {
    // read 3 bytes from xof
    uint8_t ds[3] = { 0 };
    shake128_xof_squeeze(&xof, ds, 3);

    // split 3 bytes into two 12-bit samples
    const uint16_t d1 = ((uint16_t) ds[0]) | (((uint16_t) (ds[1] & 0xF)) << 8),
                   d2 = ((uint16_t) ds[1] >> 4) | (((uint16_t) ds[2]) << 4);

    // sample d1
    if (d1 < Q) {
      a->cs[i++] = d1;
    }

    // sample d2
    if (d2 < Q && i < 256) {
      a->cs[i++] = d2;
    }
  }
}

/**
 * Initialize SHAKE256 XOF as a PRF by absorbing 32-byte `seed` and byte
 * `b`, then read `len` bytes of data from the PRF into the buffer
 * pointed to by `out`.
 *
 * @param[in] seed 32 bytes.
 * @param[in] b 1 byte.
 * @param[out] out Output buffer of length `len`.
 * @param[in] len Output buffer length.
 */
static inline void prf(const uint8_t seed[static 32], const uint8_t b, uint8_t * const out, const size_t len) {
  // populate `buf` with `seed` and byte `b`
  uint8_t buf[33] = { 0 };
  memcpy(buf, seed, 32);
  buf[32] = b;

  // absorb `buf` into SHAKE256 XOF, write `len` bytes to `out`
  shake256_xof_once(buf, sizeof(buf), out, len);
}

// Function to sample polynomial coefficients from centered binomial
// distribution (CBD) using factor eta and bytes from prf data `prf`.
#define DEF_POLY_SAMPLE_CBD(ETA) \
  static inline void poly_sample_cbd_eta ## ETA (poly_t * const p, const uint8_t seed[32], const uint8_t b) { \
    /* read 64 * eta bytes of data from prf */ \
    uint8_t buf[64 * ETA] = { 0 }; \
    prf(seed, b, buf, sizeof(buf)); \
    \
    for (size_t i = 0; i < 256; i++) { \
      uint16_t x = 0; \
      for (size_t j = 0; j < ETA; j++) { \
        const size_t ofs = 2 * i * ETA + j; \
        x += (buf[ofs / 8] >> (ofs % 8)) & 0x01; \
      } \
      \
      uint16_t y = 0; \
      for (size_t j = 0; j < ETA; j++) { \
        const size_t ofs = 2 * i * ETA + ETA + j; \
        y += (buf[ofs / 8] >> (ofs % 8)) & 0x01; \
      } \
      \
      p->cs[i] = (x + (Q - y)) % Q; /* (x - y) % Q */ \
    } \
  }

DEF_POLY_SAMPLE_CBD(3) // PKE512_ETA1 = 3
DEF_POLY_SAMPLE_CBD(2) // PKE512_ETA2 = 2

// Compute number theoretic transform (NTT) of given polynomial p E R_q.
static inline void poly_ntt(poly_t * const p) {
  uint8_t k = 1;
  for (uint16_t len = 128; len >= 2; len /= 2) {
    for (uint16_t start = 0; start < 256; start += 2 * len) {
      const uint16_t zeta = NTT_LUT[k++];

      for (uint16_t j = start; j < start + len; j++) {
        const uint16_t t = (zeta * p->cs[j + len]) % Q;
        p->cs[j + len] = (p->cs[j] + (Q - t)) % Q; // (p[j] - t) % Q
        p->cs[j] = (p->cs[j] + t) % Q;
      }
    }
  }
}

// Compute the inverse number theoretic transform (NTT) of given
// polynomial p E T_q.
static inline void poly_inv_ntt(poly_t * const p) {
  uint8_t k = 127;
  for (uint16_t len = 2; len <= 128; len *= 2) {
    for (uint16_t start = 0; start < 256; start += 2 * len) {
      const uint16_t zeta = NTT_LUT[k--];

      for (uint16_t j = start; j < start + len; j++) {
        const uint16_t t = p->cs[j];
        p->cs[j] = (t + p->cs[j + len]) % Q; // (t + p[j + len]) % Q
        p->cs[j + len] = (zeta * ((p->cs[j + len] + (Q - t)))) % Q;
      }
    }
  }

  for (size_t i = 0; i < 256; i++) {
    p->cs[i] = ((uint32_t) p->cs[i] * 3303) % Q;
  }
}

// add polynomial `a` to polynomial `b` component-wise, and store the
// results in `a`.
static inline void poly_add(poly_t * const restrict a, const poly_t * const restrict b) {
  for (size_t i = 0; i < 256; i++) {
    a->cs[i] = ((uint32_t) a->cs[i] + (uint32_t) b->cs[i]) % Q;
  }
}

// Subtract polynomial `b` from polynomial `a` component-wise, and store the
// results in `a`.
static inline void poly_sub(poly_t * const restrict a, const poly_t * const restrict b) {
  for (size_t i = 0; i < 256; i++) {
    a->cs[i] = ((uint32_t) a->cs[i] + (uint32_t) (Q - b->cs[i])) % Q;
  }
}

// multiply polynomial `a` to polynomial `b` and store the results in
// `c`.  `a` and `b` are assumed to be in NTT.
static inline void poly_mul(poly_t * const restrict c, const poly_t * const restrict a, const poly_t * const restrict b) {
  for (size_t i = 0; i < 128; i++) {
    const uint32_t a0 = a->cs[2 * i],
                   a1 = a->cs[2 * i + 1],
                   b0 = b->cs[2 * i],
                   b1 = b->cs[2 * i + 1];
    c->cs[2 * i] = (a0 * b0 + a1 * b1 * MUL_LUT[i]) % Q;
    c->cs[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
  }
}

// Encode 12-bit polynomial coefficients into 384 bytes
static void poly_encode(uint8_t out[static 384], const poly_t * const a) {
  for (size_t i = 0; i < 128; i++) {
    const uint16_t a0 = a->cs[2 * i],
                   a1 = a->cs[2 * i + 1];
    out[3 * i] = (uint8_t) a0;
    out[3 * i + 1] = (uint8_t) (((a0 & 0xf00) >> 4) | ((a1 & 0x0f) << 4));
    out[3 * i + 2] = (uint8_t) ((a1 & 0xff0) >> 4);
  }
}

// Compress coefficients to 10 bits and then encode them as 320 bytes.
static inline void poly_encode_10bit(uint8_t out[static 320], const poly_t * const p) {
  for (size_t i = 0; i < 64; i++) {
    // compress (shift and round)
    const uint16_t p0 = (p->cs[4 * i] >> 2) + ((p->cs[4 * i] >> 2) & 1),
                   p1 = (p->cs[4 * i + 1] >> 2) + ((p->cs[4 * i + 1] >> 1) & 1),
                   p2 = (p->cs[4 * i + 2] >> 2) + ((p->cs[4 * i + 2] >> 1) & 1),
                   p3 = (p->cs[4 * i + 3] >> 2) + ((p->cs[4 * i + 3] >> 1) & 1);

    out[5 * i + 0] = (p0) & 0xff;
    out[5 * i + 1] = ((p0 >> 8) & 0x03) | ((p1 & 0x3f) << 2);
    out[5 * i + 2] = ((p1 >> 6) & 0xf) | ((p2 & 0xf) << 4);
    out[5 * i + 3] = ((p2 >> 4) & 0x3f) | ((p3 & 0x3) << 6);
    out[5 * i + 4] = (p3 >> 2) & 0xff;
  }
}

// Compress coefficients to 4 bits and then encode them as 128 bytes.
static inline void poly_encode_4bit(uint8_t out[static 128], const poly_t * const p) {
  for (size_t i = 0; i < 128; i++) {
    // compress (shift and round)
    const uint16_t p0 = (p->cs[2 * i] >> 8) + ((p->cs[2 * i] >> 7) & 1),
                   p1 = (p->cs[2 * i + 1] >> 8) + ((p->cs[2 * i + 1] >> 7) & 1);
    out[i] = p0 | (p1 << 4);
  }
}

// Compress coefficients to 1 bit and then encode them as 32 bytes.
static inline void poly_encode_1bit(uint8_t out[static 32], const poly_t * const p) {
  for (size_t i = 0; i < 32; i++) {
    out[i] = (((p->cs[8 * i + 0] > 1664)) & 1) |
             (((p->cs[8 * i + 1] > 1664) & 1) << 1) |
             (((p->cs[8 * i + 2] > 1664) & 1) << 2) |
             (((p->cs[8 * i + 3] > 1664) & 1) << 3) |
             (((p->cs[8 * i + 4] > 1664) & 1) << 4) |
             (((p->cs[8 * i + 5] > 1664) & 1) << 5) |
             (((p->cs[8 * i + 6] > 1664) & 1) << 6) |
             (((p->cs[8 * i + 7] > 1664) & 1) << 7);
  }
}

// decode 12-bit polynomial coefficients from 384 byte buffer
// FIXME: should we check for invalid coefficients here?
static void poly_decode(poly_t * const p, const uint8_t b[static 384]) {
  for (size_t i = 0; i < 128; i++) {
    const uint8_t b0 = b[3 * i],
                  b1 = b[3 * i + 1],
                  b2 = b[3 * i + 2];
    p->cs[2 * i] = ((uint16_t) b0) | ((((uint16_t) b1) & 0xf) << 4);
    p->cs[2 * i + 1] = (((uint16_t) b1 & 0xf0) >> 4) | (((uint16_t) b2) << 4);
  }
}

// Decode 1-bit coefficients from 32 bytes and then decompress them
// (e.g., multiply by 1665).
static void poly_decode_1bit(poly_t * const p, const uint8_t b[static 32]) {
  for (size_t i = 0; i < 256; i++) {
    p->cs[i] = 1665 * ((b[i / 8] >> (i % 8)) & 1);
  }
}

// Decode 10-bit coefficients from 320 bytes and then decompress them
// (e.g., multiply by 3).
static void poly_decode_10bit(poly_t * const p, const uint8_t b[static 320]) {
  for (size_t i = 0; i < 64; i++) {
    const uint16_t b0 = b[5 * i],
                   b1 = b[5 * i + 1],
                   b2 = b[5 * i + 2],
                   b3 = b[5 * i + 3],
                   b4 = b[5 * i + 4];

    p->cs[4 * i + 0] = 3 * (b0 | ((b1 & 3) << 8));
    p->cs[4 * i + 1] = 3 * ((b1 >> 2) | ((b2 & 0xf) << 6));
    p->cs[4 * i + 2] = 3 * ((b2 >> 4) | ((b3 & 0x3f) << 4));
    p->cs[4 * i + 3] = 3 * ((b3 >> 6) | (b4 << 2));
  }
}

// Decode 4-bit coefficients from 128 bytes and then decompress them
// (e.g., multiply by 208).
static inline void poly_decode_4bit(poly_t * const p, const uint8_t b[static 128]) {
  for (size_t i = 0; i < 128; i++) {
    const uint16_t b0 = b[i];

    p->cs[2 * i + 0] = 208 * ((b0 & 0x0f) << 8);
    p->cs[2 * i + 1] = 208 * ((b0 & 0xf0) << 4);
  }
}

// define operations for NxN matrices and N-dim vectors.
#define DEFINE_MAT_VEC_OPS(N) \
  /* multiply NxN matrix of polynomials in `mat` by vector of */ \
  /* polynomials in `vec` and store the product in vector `out`. */ \
  static inline void mat ## N ## _mul(poly_t out[static N], poly_t mat[static N*N], poly_t vec[static N]) { \
    /* clear result */ \
    memset(out, 0, sizeof(N * sizeof(poly_t))); \
    for (size_t y = 0; y < N; y++) { \
      for (size_t x = 0; x < N; x++) { \
        poly_t prod = { 0 }; \
        poly_mul(&prod, mat + (N * y + x), vec + x); \
        poly_add(out + y, &prod); \
      } \
    } \
  } \
  \
  /* add coefficients in vectors `a` and `b` and store the results in `a`. */ \
  static inline void vec ## N ## _add(poly_t a[static N], const poly_t b[static N]) { \
    for (size_t i = 0; i < N; i++) { \
      poly_add(a + i, b + i); \
    } \
  } \
  \
  /* multiple elements of vectors `a` and `b`, sum results, and store the results in `c`. */ \
  static inline void vec ## N ## _mul(poly_t * const restrict c, const poly_t a[static N], const poly_t b[static N]) { \
    /* clear result */ \
    memset(c, 0, sizeof(sizeof(poly_t))); \
    for (size_t i = 0; i < N; i++) { \
      poly_t prod = { 0 }; \
      poly_mul(&prod, a + i, b + i); \
      poly_add(c, &prod); \
    } \
  }

// define mat3 and vec2 functions
DEFINE_MAT_VEC_OPS(2)

// Constant-time difference.  Returns true if `a` and `b` differ and
// false they are the identical.
static inline bool ct_diff(const uint8_t * const restrict a, const uint8_t * const restrict b, const size_t len) {
  uint8_t r = 0;
  for (size_t i = 0; i < len; i++) {
    r |= (a[i] ^ b[i]);
  }

  return r == 0;
}

// Constant-time copy: copy from `a` if `sel` is `0` and `b` if `sel` is
// `1`.
static inline void ct_copy(uint8_t c[static 32], const bool sel, const uint8_t a[static 32], const uint8_t b[static 32]) {
  const uint8_t mask = sel ? 0xff : 0x00;
  for (size_t i = 0; i < 32; i++) {
    c[i] = (a[i] & mask) ^ (b[i] & ~mask);
  }
}

/**
 * Generate PKE512 encryption and decryption key from given 32-byte
 * seed.
 *
 * @param[out] ek PKE512 encryption key.
 * @param[out] dk PKE512 decryption key.
 * @param[in] seed Input 32-byte seed.
 */
static inline void pke512_keygen(uint8_t ek[static PKE512_EK_SIZE], uint8_t dk[static PKE512_DK_SIZE], const uint8_t seed[static 32]) {
  // get sha3-512 hash of seed, get rho and sigma (each 32 bytes)
  uint8_t rs[64] = { 0 }; // rho = rs[0,31], sigma = rs[32,63]
  sha3_512(seed, 32, rs); // rho, sigma = sha3-512(seed)
  const uint8_t * const sigma = rs + 32; // sigma

  // populate A hat
  poly_t a[PKE512_K * PKE512_K] = { 0 };
  for (size_t i = 0; i < PKE512_K; i++) {
    for (size_t j = 0; j < PKE512_K; j++) {
      // sample polynomial
      poly_sample_ntt(a + (PKE512_K * i + j), rs, i, j);
    }
  }

  // sample s and e coefficients from CBD
  // (note: sampling is done in R_q, not in NTT domain)
  poly_t se[2 * PKE512_K] = { 0 }; // s = se[0, k], e = se[k, 2k-1]
  for (size_t i = 0; i < 2 * PKE512_K; i++) {
    // sample polynomial coefficients from CBD(ETA1)
    poly_sample_cbd_eta3(se + i, sigma, i);

    // apply NTT to polynomial coefficients (R_q -> T_q)
    poly_ntt(se + i);
  }

  // t = As + e (NTT)
  poly_t t[PKE512_K] = { 0 }, *s = se, *e = se + PKE512_K;
  mat2_mul(t, a, s); // t = As
  vec2_add(t, e); // t += e

  // encode t (NTT)
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_encode(ek + (386 * i), t + i);
  }

  // ek <- t || rho
  memcpy(ek + (PKE512_K * 384), rs, 32);

  // dk <- s (NTT)
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_encode(dk + (386 * i), se + i);
  }
}

static inline void pke512_encrypt(uint8_t ct[static PKE512_CT_SIZE], const uint8_t ek[static PKE512_EK_SIZE], const uint8_t m[static 32], const uint8_t enc_rand[static 32]) {
  // decode t from ek
  poly_t t[PKE512_K] = { 0 };
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_decode(t + i, ek + (384 * i));
  }

  // decode rho from ek
  const uint8_t * const rho = ek + 384 * PKE512_K;

  // populate A hat (transposed)
  poly_t a[PKE512_K * PKE512_K] = { 0 };
  for (size_t i = 0; i < PKE512_K; i++) {
    for (size_t j = 0; j < PKE512_K; j++) {
      // sample polynomial (with i and j transposed)
      poly_sample_ntt(a + (PKE512_K * i + j), rho, j, i);
    }
  }

  // populate r vector (in NTT)
  poly_t r[PKE512_K] = { 0 };
  for (size_t i = 0; i < PKE512_K; i++) {
    // sample polynomial coefficients from CBD(ETA1)
    poly_sample_cbd_eta3(r + i, enc_rand, i);

    // apply NTT to polynomial coefficients (R_q -> T_q)
    poly_ntt(r + i);
  }

  // populate e1 vector (not in NTT)
  poly_t e1[PKE512_K] = { 0 };
  for (size_t i = 0; i < PKE512_K; i++) {
    // sample polynomial coefficients from CBD(ETA2)
    poly_sample_cbd_eta2(e1 + i, enc_rand, PKE512_K + i);
  }

  // populate e2 polynomial (not in NTT)
  poly_t e2 = { 0 };
  poly_sample_cbd_eta2(&e2, enc_rand, 2 * PKE512_K);

  // u = (A*r)
  poly_t u[PKE512_K] = { 0 };
  mat2_mul(u, a, r);

  // u = inverse NTT(u)
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_inv_ntt(u + i);
  }

  // u += e1
  vec2_add(u, e1);

  // encode u, append to ct
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_encode_10bit(ct + 320 * i, u + i);
  }

  // decode and decompress message into polynomial
  poly_t mu;
  poly_decode_1bit(&mu, m);

  poly_t v = { 0 };
  vec2_mul(&v, t, r); // v = t * r
  poly_inv_ntt(&v);   // v = inverse NTT(v)
  poly_add(&v, &e2);  // v += e2
  poly_add(&v, &mu);  // v += mu

  // encode v, append to ct
  poly_encode_4bit(ct + 320 * PKE512_K, &v);
}

static void pke512_decrypt(uint8_t m[static 32], const uint8_t dk[static PKE512_DK_SIZE], const uint8_t ct[PKE512_CT_SIZE]) {
  // decode u
  poly_t u[PKE512_K] = { 0 };
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_decode_10bit(u + i, ct + 32 * PKE512_DU * i);
  }

  // decode v
  poly_t v = { 0 };
  poly_decode_4bit(&v, ct + 32 * PKE512_DU * PKE512_K);

  // decode ŝ
  poly_t s[PKE512_K] = { 0 };
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_decode(s + i, dk + 384 * i);
  }

  poly_t su = { 0 }; // su = s * u
  for (size_t i = 0; i < PKE512_K; i++) {
    poly_t tmp = { 0 };
    poly_ntt(u + i); // u[i] = NTT(u[i])
    poly_mul(&tmp, s + i, u + i); // tmp = s[i] * u[i]
    poly_add(&su, &tmp);
  }
  poly_inv_ntt(&su); // su = inverse NTT(su)

  poly_t w = v;
  poly_sub(&w, &su); // w -= su

  // encode w coefficients as 1-bit, write to output
  poly_encode_1bit(m, &w);
}

void fips203_kem512_keygen(uint8_t ek[static FIPS203_KEM512_EK_SIZE], uint8_t dk[static FIPS203_KEM512_DK_SIZE], const uint8_t seed[static 64]) {
  const uint8_t * const z = seed; // implicit rejection seed (32 random bytes)

  // generate ek and dk
  const uint8_t * const d = seed + 32; // pke512_keygen() seed (32 random bytes)
  pke512_keygen(ek, dk, d);

  // KEM: populate dk with ek, sha3-256(ek), and z
  memcpy(dk + PKE512_DK_SIZE, ek, PKE512_EK_SIZE);
  sha3_256(ek, PKE512_EK_SIZE, dk + PKE512_DK_SIZE + PKE512_EK_SIZE);
  memcpy(dk + PKE512_DK_SIZE + PKE512_EK_SIZE + 32, z, 32);
}

void fips203_kem512_encaps(uint8_t k[static 32], uint8_t ct[static FIPS203_KEM512_CT_SIZE], const uint8_t ek[static FIPS203_KEM512_EK_SIZE], const uint8_t seed[static 32]) {
  uint8_t data[64] = { 0 };
  memcpy(data, seed, 32); // append seed
  sha3_256(ek, PKE512_EK_SIZE, data + 32); // append sha3-256(ek)

  uint8_t kr[64] = { 0 };
  sha3_512(data, 64, kr); // (K, r) <- sha3-512(data)

  memcpy(k, kr, 32); // copy shared key
  pke512_encrypt(ct, ek, seed, kr + 32); // ct <- pke.encrypt(ek, seed, r)
}

// Decapsulate shared key `k` from ciphertext `ct` using KEM decryption
// key `dk_kem` with implicit rejection.
void fips203_kem512_decaps(uint8_t k[static 32], const uint8_t ct[static FIPS203_KEM512_CT_SIZE], const uint8_t dk_kem[static FIPS203_KEM512_DK_SIZE]) {
  const uint8_t * const dk_pke = dk_kem;
  const uint8_t * const ek_pke = dk_kem + 384 * PKE512_K;
  const uint8_t * const h = dk_kem + (2 * 384 * PKE512_K + 32);
  const uint8_t * const z = dk_kem + (2 * 384 * PKE512_K + 64);

  // decrypt m
  uint8_t mh[64] = { 0 };
  pke512_decrypt(mh, dk_pke, ct);
  memcpy(mh + 32, h, 32); // copy hash

  uint8_t kr[64] = { 0 };
  sha3_512(mh, 64, kr); // (K', r') <- sha3-512(m || r)

  // zc = z || ct
  uint8_t zc[32 + PKE512_CT_SIZE] = { 0 };
  memcpy(zc, z, 32);
  memcpy(zc + 32, ct, PKE512_CT_SIZE);

  // rk: generate implicit rejection key from z and ciphertext
  uint8_t k_rej[32] = { 0 };
  shake256(zc, sizeof(zc), k_rej); // K_rej = J(z||c)

  uint8_t ct2[PKE512_CT_SIZE] = { 0 };
  pke512_encrypt(ct2, ek_pke, mh, kr + 32); // ct2 <- pke.encrypt(ek, m', r')

  ct_copy(k, ct_diff(ct, ct2, PKE512_CT_SIZE), kr, k_rej);
}

#ifdef TEST_FIPS203
#include <stdio.h>

// write polynomial coefficients to given file handle
static void poly_write(FILE *fh, const poly_t * const p) {
  for (size_t i = 0; i < 256; i++) {
    fprintf(fh, "%s%d", (i ? ", " : ""), p->cs[i]);
  }
}

static void test_poly_ntt_roundtrip(void) {
  static const struct {
    const char *name; // test name
    const poly_t poly; // test polynomial
  } TESTS[] = {{
    .name = "0-255",
    .poly = {
      .cs = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
      },
    },
  }, {
    .name = "256-511",
    .poly = {
      .cs = {
        256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511,
      },
    },
  }, {
    .name = "512-767",
    .poly = {
      .cs = {
        512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767,
      },
    },
  }, {
    .name = "3000-3255",
    .poly = {
      .cs = {
        3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3020, 3021, 3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3034, 3035, 3036, 3037, 3038, 3039, 3040, 3041, 3042, 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3056, 3057, 3058, 3059, 3060, 3061, 3062, 3063, 3064, 3065, 3066, 3067, 3068, 3069, 3070, 3071, 3072, 3073, 3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085, 3086, 3087, 3088, 3089, 3090, 3091, 3092, 3093, 3094, 3095, 3096, 3097, 3098, 3099, 3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3121, 3122, 3123, 3124, 3125, 3126, 3127, 3128, 3129, 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3140, 3141, 3142, 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150, 3151, 3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3164, 3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182, 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190, 3191, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224, 3225, 3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242, 3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251, 3252, 3253, 3254, 3255,
      },
    },
  }, {
    .name = "3073-3328",
    .poly = {
      .cs = {
        3073, 3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085, 3086, 3087, 3088, 3089, 3090, 3091, 3092, 3093, 3094, 3095, 3096, 3097, 3098, 3099, 3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3121, 3122, 3123, 3124, 3125, 3126, 3127, 3128, 3129, 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3140, 3141, 3142, 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150, 3151, 3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3164, 3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182, 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190, 3191, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224, 3225, 3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242, 3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251, 3252, 3253, 3254, 3255, 3256, 3257, 3258, 3259, 3260, 3261, 3262, 3263, 3264, 3265, 3266, 3267, 3268, 3269, 3270, 3271, 3272, 3273, 3274, 3275, 3276, 3277, 3278, 3279, 3280, 3281, 3282, 3283, 3284, 3285, 3286, 3287, 3288, 3289, 3290, 3291, 3292, 3293, 3294, 3295, 3296, 3297, 3298, 3299, 3300, 3301, 3302, 3303, 3304, 3305, 3306, 3307, 3308, 3309, 3310, 3311, 3312, 3313, 3314, 3315, 3316, 3317, 3318, 3319, 3320, 3321, 3322, 3323, 3324, 3325, 3326, 3327, 3328,
      },
    },
  }};

  for (size_t i = 0; i < sizeof(TESTS)/sizeof(TESTS[0]); i++) {
    // copy poly
    poly_t got = TESTS[i].poly;

    // calculate invntt(ntt(poly))
    poly_ntt(&got);
    poly_inv_ntt(&got);

    // check for expected value
    if (memcmp(&got, &TESTS[i].poly, sizeof(poly_t))) {
      fprintf(stderr, "test_poly_ntt(\"%s\") failed, got:\n", TESTS[i].name);
      poly_write(stderr, &got);
      fprintf(stderr, "\nexp:\n");
      poly_write(stderr, &(TESTS[i].poly));
      fprintf(stderr, "\n");
    }
  }
}

static void test_poly_sample_ntt(void) {
  static const struct {
    const char *name; // test name
    const uint8_t x, y; // coordinates
    const poly_t exp; // expected polynomial
  } TESTS[] = {{
    .name = "0, 0",
    .x = 0,
    .y = 0,
    .exp = {
      .cs = {
        // expected coefficients, seed = { 0 }, x = 0, y = 0
        0xb80, 0xbc9, 0x154, 0x4a0, 0xcab, 0x6ac, 0x99a, 0x8ed, 0xad4, 0x957, 0x19d, 0x102, 0x729, 0x601, 0x89b, 0xa78, 0xc62, 0x6d5, 0xaa9, 0x10a, 0x42e, 0x2e3, 0x4d5, 0x419, 0x556, 0x8b8, 0xb9c, 0x5bc, 0x5f7, 0x799, 0x59f, 0xa16, 0xa97, 0x8a1, 0x0bc, 0xc7c, 0xc9e, 0x529, 0x98b, 0x466, 0x056, 0x11e, 0x06b, 0x376, 0x075, 0xa95, 0xb2a, 0x541, 0x652, 0x182, 0xc5a, 0x6c6, 0x2c8, 0x9f4, 0x2c5, 0xb10, 0xc85, 0x825, 0xb55, 0x245, 0x9a4, 0x893, 0x95b, 0x82d, 0x747, 0xbd4, 0x617, 0xc6c, 0x7f3, 0x924, 0x90d, 0x4a5, 0x508, 0x505, 0x899, 0x17c, 0x9b5, 0x92c, 0xb7c, 0x916, 0x2d4, 0x4be, 0x1db, 0xc50, 0x48d, 0xc20, 0x015, 0x7e2, 0x643, 0x348, 0xa50, 0x1fb, 0x0a9, 0x4c1, 0x3ea, 0xb5d, 0x07f, 0x309, 0x73d, 0x138, 0x8ac, 0x51f, 0x643, 0x9ba, 0x574, 0xcdc, 0x2d5, 0x1a1, 0x84c, 0x363, 0x597, 0xc01, 0x29d, 0x536, 0x0c8, 0x52c, 0xa23, 0x72f, 0x6ae, 0x2ad, 0xc82, 0x105, 0x572, 0x1af, 0xb8f, 0x5a8, 0x112, 0x9b6, 0x176, 0x690, 0x42c, 0x007, 0x37a, 0xbb4, 0x7d9, 0x594, 0x0bc, 0x141, 0x25c, 0x7bf, 0x970, 0x168, 0x295, 0x4ce, 0xb07, 0x180, 0x13d, 0x94e, 0xbaa, 0xa54, 0x2fd, 0x7b1, 0xb07, 0x50a, 0x903, 0x244, 0x14b, 0xa15, 0xbb0, 0xb9f, 0x961, 0xc13, 0x885, 0xbdf, 0x71c, 0xcbb, 0x398, 0x666, 0x712, 0x21a, 0x6c9, 0xbc7, 0x834, 0x929, 0x6aa, 0xa2c, 0xac0, 0x480, 0x1f3, 0x3dd, 0x229, 0xc54, 0x13a, 0x979, 0x9d4, 0x7ef, 0x0c7, 0x7f5, 0xb6a, 0x233, 0xa8e, 0x09f, 0x973, 0xb0d, 0x91b, 0xc55, 0x3c7, 0x8a3, 0x958, 0x0fd, 0x786, 0x57e, 0x5e9, 0xac1, 0x5ec, 0x866, 0x0bc, 0xa64, 0x543, 0x808, 0x18f, 0xa6e, 0x755, 0x93a, 0x481, 0x4f2, 0x012, 0x53f, 0xb4a, 0xb03, 0x826, 0x54c, 0x101, 0x968, 0x3f2, 0xa87, 0x188, 0x8e2, 0x625, 0x8ce, 0x9de, 0xcda, 0x040, 0x60c, 0xb93, 0x078, 0xc7b, 0xb50, 0x53b, 0x9a1, 0x66d, 0xc5e, 0x996, 0x7c7, 0x7b3, 0x71d, 0x347, 0x6b9, 0x702, 0x3df, 0x7aa, 0x7bd, 0xc97, 0xac1, 0x163, 0x813
      },
    },
  }, {
    .name = "2, 3",
    .x = 2,
    .y = 3,
    .exp = {
      .cs = {
        // expected coefficients, seed = { 0 }, x = 2, y = 3
        0x2ef, 0x75d, 0xbf1, 0x4a4, 0x09b, 0x4bd, 0x58d, 0x1d8, 0x996, 0x82c, 0x0f3, 0x6b7, 0x32a, 0x9ad, 0x4f4, 0xb18, 0xab9, 0x4d3, 0xa96, 0x676, 0x742, 0x4cc, 0x3bb, 0x145, 0x5e3, 0x591, 0xb34, 0x82e, 0x670, 0x84a, 0x76b, 0x273, 0xb0b, 0x0f9, 0x5c2, 0x9bd, 0x7ef, 0xa1c, 0x161, 0xc5a, 0xc22, 0x87b, 0x9a1, 0x9b2, 0x797, 0x6a5, 0xb41, 0x635, 0xa0b, 0x60c, 0x859, 0x833, 0x991, 0xa92, 0xc80, 0x762, 0x826, 0xc75, 0x831, 0xcfe, 0x3b3, 0x435, 0x7eb, 0x3f4, 0x148, 0xa0b, 0x3f4, 0x27a, 0x930, 0x4be, 0x4a1, 0x6ac, 0xa36, 0x45d, 0x751, 0x018, 0x799, 0x785, 0x697, 0xc7e, 0x0aa, 0xcb3, 0xc12, 0x72d, 0x5bf, 0x8bc, 0x8e3, 0x0d1, 0xb60, 0x162, 0x86c, 0xb19, 0x084, 0x4aa, 0xad2, 0x0ef, 0x00c, 0xc08, 0x95c, 0x4df, 0x233, 0x705, 0x573, 0x090, 0x500, 0x7b8, 0xafa, 0x829, 0x0f0, 0xa32, 0x556, 0xcf6, 0x2ab, 0x7a2, 0x5a7, 0x325, 0x39a, 0x265, 0xb9c, 0xa33, 0x218, 0x593, 0x16d, 0x2e2, 0x316, 0x134, 0x1fd, 0x443, 0xc93, 0x1f7, 0x3aa, 0xb65, 0x17d, 0x8f0, 0x12e, 0x624, 0x7f6, 0xc22, 0xca3, 0x21f, 0xbb5, 0x48d, 0x3eb, 0x00a, 0x8e5, 0xb6a, 0x687, 0x745, 0x415, 0x4e7, 0x422, 0x2c8, 0x3e3, 0x1a3, 0x67e, 0x3ce, 0x582, 0x106, 0x79e, 0x1c6, 0x7cb, 0x165, 0x199, 0x959, 0x987, 0xb55, 0x95e, 0x71f, 0xcf6, 0x8c1, 0x98d, 0x966, 0x847, 0x7b0, 0x0ea, 0x3d2, 0x256, 0x195, 0x554, 0xb00, 0x101, 0x2dc, 0xba7, 0x55b, 0x477, 0x575, 0x978, 0xaa1, 0x3df, 0x5ac, 0xc44, 0x8a5, 0xc85, 0x00f, 0x130, 0xa49, 0x9ea, 0x92e, 0x9aa, 0x43d, 0x047, 0x34a, 0x97c, 0x4b8, 0xa62, 0x2c2, 0x926, 0x1ea, 0xa8e, 0xcac, 0xcac, 0x509, 0x222, 0x7ff, 0x545, 0x44a, 0x5f3, 0x8a2, 0x22e, 0x4f1, 0x53a, 0x5ac, 0x9e3, 0x0bf, 0x3b5, 0x943, 0x6cb, 0x3a3, 0xc7e, 0xc27, 0xa2e, 0x79f, 0x7d9, 0x1ac, 0xbfe, 0x84d, 0x67e, 0x5e2, 0x497, 0x5b9, 0x873, 0x21e, 0x7e9, 0xb18, 0x25b, 0x0de, 0x5d6, 0x837, 0x135, 0x88a, 0xc27, 0x017, 0x090, 0x0ed, 0x3e9, 0xc5c
      },
    },
  }};

  const uint8_t SEED[32] = { 0 };

  for (size_t i = 0; i < sizeof(TESTS)/sizeof(TESTS[0]); i++) {
    // sample polynomial from NTT
    poly_t got = { 0 };
    poly_sample_ntt(&got, SEED, TESTS[i].x, TESTS[i].y);

    // check for expected value
    if (memcmp(&got, &TESTS[i].exp, sizeof(poly_t))) {
      fprintf(stderr, "test_poly_sample_ntt(\"%s\") failed, got:\n", TESTS[i].name);
      poly_write(stderr, &got);
      fprintf(stderr, "\nexp:\n");
      poly_write(stderr, &(TESTS[i].exp));
      fprintf(stderr, "\n");
    }
  }
}

static void test_poly_add(void) {
  static const struct {
    const char *name; // test name
    const poly_t a, b, // operands
                 exp; // expected result
  } TESTS[] = {{
    .name = "0-255 + 256-511",
    .a = {
      .cs = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
      },
    },

    .b = {
      .cs = {
        256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511,
      },
    },

    .exp = {
      .cs = {
        256, 258, 260, 262, 264, 266, 268, 270, 272, 274, 276, 278, 280, 282, 284, 286, 288, 290, 292, 294, 296, 298, 300, 302, 304, 306, 308, 310, 312, 314, 316, 318, 320, 322, 324, 326, 328, 330, 332, 334, 336, 338, 340, 342, 344, 346, 348, 350, 352, 354, 356, 358, 360, 362, 364, 366, 368, 370, 372, 374, 376, 378, 380, 382, 384, 386, 388, 390, 392, 394, 396, 398, 400, 402, 404, 406, 408, 410, 412, 414, 416, 418, 420, 422, 424, 426, 428, 430, 432, 434, 436, 438, 440, 442, 444, 446, 448, 450, 452, 454, 456, 458, 460, 462, 464, 466, 468, 470, 472, 474, 476, 478, 480, 482, 484, 486, 488, 490, 492, 494, 496, 498, 500, 502, 504, 506, 508, 510, 512, 514, 516, 518, 520, 522, 524, 526, 528, 530, 532, 534, 536, 538, 540, 542, 544, 546, 548, 550, 552, 554, 556, 558, 560, 562, 564, 566, 568, 570, 572, 574, 576, 578, 580, 582, 584, 586, 588, 590, 592, 594, 596, 598, 600, 602, 604, 606, 608, 610, 612, 614, 616, 618, 620, 622, 624, 626, 628, 630, 632, 634, 636, 638, 640, 642, 644, 646, 648, 650, 652, 654, 656, 658, 660, 662, 664, 666, 668, 670, 672, 674, 676, 678, 680, 682, 684, 686, 688, 690, 692, 694, 696, 698, 700, 702, 704, 706, 708, 710, 712, 714, 716, 718, 720, 722, 724, 726, 728, 730, 732, 734, 736, 738, 740, 742, 744, 746, 748, 750, 752, 754, 756, 758, 760, 762, 764, 766,
      },
    },
  }, {
    .name = "1000-1255 + 3000-3255 (test modulus)",
    .a = {
      .cs = {
        1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1133, 1134, 1135, 1136, 1137, 1138, 1139, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150, 1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1160, 1161, 1162, 1163, 1164, 1165, 1166, 1167, 1168, 1169, 1170, 1171, 1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, 1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195, 1196, 1197, 1198, 1199, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1220, 1221, 1222, 1223, 1224, 1225, 1226, 1227, 1228, 1229, 1230, 1231, 1232, 1233, 1234, 1235, 1236, 1237, 1238, 1239, 1240, 1241, 1242, 1243, 1244, 1245, 1246, 1247, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255
      },
    },

    .b = {
      .cs = {
        3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3020, 3021, 3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3034, 3035, 3036, 3037, 3038, 3039, 3040, 3041, 3042, 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3056, 3057, 3058, 3059, 3060, 3061, 3062, 3063, 3064, 3065, 3066, 3067, 3068, 3069, 3070, 3071, 3072, 3073, 3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085, 3086, 3087, 3088, 3089, 3090, 3091, 3092, 3093, 3094, 3095, 3096, 3097, 3098, 3099, 3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3121, 3122, 3123, 3124, 3125, 3126, 3127, 3128, 3129, 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3140, 3141, 3142, 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150, 3151, 3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3164, 3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182, 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190, 3191, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224, 3225, 3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242, 3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251, 3252, 3253, 3254, 3255
      },
    },

    .exp = {
      .cs = {
        671, 673, 675, 677, 679, 681, 683, 685, 687, 689, 691, 693, 695, 697, 699, 701, 703, 705, 707, 709, 711, 713, 715, 717, 719, 721, 723, 725, 727, 729, 731, 733, 735, 737, 739, 741, 743, 745, 747, 749, 751, 753, 755, 757, 759, 761, 763, 765, 767, 769, 771, 773, 775, 777, 779, 781, 783, 785, 787, 789, 791, 793, 795, 797, 799, 801, 803, 805, 807, 809, 811, 813, 815, 817, 819, 821, 823, 825, 827, 829, 831, 833, 835, 837, 839, 841, 843, 845, 847, 849, 851, 853, 855, 857, 859, 861, 863, 865, 867, 869, 871, 873, 875, 877, 879, 881, 883, 885, 887, 889, 891, 893, 895, 897, 899, 901, 903, 905, 907, 909, 911, 913, 915, 917, 919, 921, 923, 925, 927, 929, 931, 933, 935, 937, 939, 941, 943, 945, 947, 949, 951, 953, 955, 957, 959, 961, 963, 965, 967, 969, 971, 973, 975, 977, 979, 981, 983, 985, 987, 989, 991, 993, 995, 997, 999, 1001, 1003, 1005, 1007, 1009, 1011, 1013, 1015, 1017, 1019, 1021, 1023, 1025, 1027, 1029, 1031, 1033, 1035, 1037, 1039, 1041, 1043, 1045, 1047, 1049, 1051, 1053, 1055, 1057, 1059, 1061, 1063, 1065, 1067, 1069, 1071, 1073, 1075, 1077, 1079, 1081, 1083, 1085, 1087, 1089, 1091, 1093, 1095, 1097, 1099, 1101, 1103, 1105, 1107, 1109, 1111, 1113, 1115, 1117, 1119, 1121, 1123, 1125, 1127, 1129, 1131, 1133, 1135, 1137, 1139, 1141, 1143, 1145, 1147, 1149, 1151, 1153, 1155, 1157, 1159, 1161, 1163, 1165, 1167, 1169, 1171, 1173, 1175, 1177, 1179, 1181
      },
    },
  }};

  for (size_t i = 0; i < sizeof(TESTS)/sizeof(TESTS[0]); i++) {
    // sample polynomial from NTT
    poly_t got = TESTS[i].a;
    poly_add(&got, &(TESTS[i].b));

    // check for expected value
    if (memcmp(&got, &TESTS[i].exp, sizeof(poly_t))) {
      fprintf(stderr, "test_poly_add(\"%s\") failed, got:\n", TESTS[i].name);
      poly_write(stderr, &got);
      fprintf(stderr, "\nexp:\n");
      poly_write(stderr, &(TESTS[i].exp));
      fprintf(stderr, "\n");
    }
  }
}

static void test_poly_sub(void) {
  static const struct {
    const char *name; // test name
    const poly_t a, b, // operands
                 exp; // expected result
  } TESTS[] = {{
    .name = "256-766 - 256-511 = 0-255",
    .a = {
      .cs = {
        256, 258, 260, 262, 264, 266, 268, 270, 272, 274, 276, 278, 280, 282, 284, 286, 288, 290, 292, 294, 296, 298, 300, 302, 304, 306, 308, 310, 312, 314, 316, 318, 320, 322, 324, 326, 328, 330, 332, 334, 336, 338, 340, 342, 344, 346, 348, 350, 352, 354, 356, 358, 360, 362, 364, 366, 368, 370, 372, 374, 376, 378, 380, 382, 384, 386, 388, 390, 392, 394, 396, 398, 400, 402, 404, 406, 408, 410, 412, 414, 416, 418, 420, 422, 424, 426, 428, 430, 432, 434, 436, 438, 440, 442, 444, 446, 448, 450, 452, 454, 456, 458, 460, 462, 464, 466, 468, 470, 472, 474, 476, 478, 480, 482, 484, 486, 488, 490, 492, 494, 496, 498, 500, 502, 504, 506, 508, 510, 512, 514, 516, 518, 520, 522, 524, 526, 528, 530, 532, 534, 536, 538, 540, 542, 544, 546, 548, 550, 552, 554, 556, 558, 560, 562, 564, 566, 568, 570, 572, 574, 576, 578, 580, 582, 584, 586, 588, 590, 592, 594, 596, 598, 600, 602, 604, 606, 608, 610, 612, 614, 616, 618, 620, 622, 624, 626, 628, 630, 632, 634, 636, 638, 640, 642, 644, 646, 648, 650, 652, 654, 656, 658, 660, 662, 664, 666, 668, 670, 672, 674, 676, 678, 680, 682, 684, 686, 688, 690, 692, 694, 696, 698, 700, 702, 704, 706, 708, 710, 712, 714, 716, 718, 720, 722, 724, 726, 728, 730, 732, 734, 736, 738, 740, 742, 744, 746, 748, 750, 752, 754, 756, 758, 760, 762, 764, 766,
      },
    },

    .b = {
      .cs = {
        256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511,
      },
    },

    .exp = {
      .cs = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
      },
    },
  }, {
    .name = "Z - 3000-3255 = 1000-1255 (test modulus)",
    .a = {
      .cs = {
        671, 673, 675, 677, 679, 681, 683, 685, 687, 689, 691, 693, 695, 697, 699, 701, 703, 705, 707, 709, 711, 713, 715, 717, 719, 721, 723, 725, 727, 729, 731, 733, 735, 737, 739, 741, 743, 745, 747, 749, 751, 753, 755, 757, 759, 761, 763, 765, 767, 769, 771, 773, 775, 777, 779, 781, 783, 785, 787, 789, 791, 793, 795, 797, 799, 801, 803, 805, 807, 809, 811, 813, 815, 817, 819, 821, 823, 825, 827, 829, 831, 833, 835, 837, 839, 841, 843, 845, 847, 849, 851, 853, 855, 857, 859, 861, 863, 865, 867, 869, 871, 873, 875, 877, 879, 881, 883, 885, 887, 889, 891, 893, 895, 897, 899, 901, 903, 905, 907, 909, 911, 913, 915, 917, 919, 921, 923, 925, 927, 929, 931, 933, 935, 937, 939, 941, 943, 945, 947, 949, 951, 953, 955, 957, 959, 961, 963, 965, 967, 969, 971, 973, 975, 977, 979, 981, 983, 985, 987, 989, 991, 993, 995, 997, 999, 1001, 1003, 1005, 1007, 1009, 1011, 1013, 1015, 1017, 1019, 1021, 1023, 1025, 1027, 1029, 1031, 1033, 1035, 1037, 1039, 1041, 1043, 1045, 1047, 1049, 1051, 1053, 1055, 1057, 1059, 1061, 1063, 1065, 1067, 1069, 1071, 1073, 1075, 1077, 1079, 1081, 1083, 1085, 1087, 1089, 1091, 1093, 1095, 1097, 1099, 1101, 1103, 1105, 1107, 1109, 1111, 1113, 1115, 1117, 1119, 1121, 1123, 1125, 1127, 1129, 1131, 1133, 1135, 1137, 1139, 1141, 1143, 1145, 1147, 1149, 1151, 1153, 1155, 1157, 1159, 1161, 1163, 1165, 1167, 1169, 1171, 1173, 1175, 1177, 1179, 1181
      },
    },

    .b = {
      .cs = {
        3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3020, 3021, 3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3034, 3035, 3036, 3037, 3038, 3039, 3040, 3041, 3042, 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3056, 3057, 3058, 3059, 3060, 3061, 3062, 3063, 3064, 3065, 3066, 3067, 3068, 3069, 3070, 3071, 3072, 3073, 3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085, 3086, 3087, 3088, 3089, 3090, 3091, 3092, 3093, 3094, 3095, 3096, 3097, 3098, 3099, 3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3121, 3122, 3123, 3124, 3125, 3126, 3127, 3128, 3129, 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3140, 3141, 3142, 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150, 3151, 3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3164, 3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182, 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190, 3191, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224, 3225, 3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242, 3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251, 3252, 3253, 3254, 3255
      },
    },

    .exp = {
      .cs = {
        1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1133, 1134, 1135, 1136, 1137, 1138, 1139, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150, 1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1160, 1161, 1162, 1163, 1164, 1165, 1166, 1167, 1168, 1169, 1170, 1171, 1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, 1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195, 1196, 1197, 1198, 1199, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1220, 1221, 1222, 1223, 1224, 1225, 1226, 1227, 1228, 1229, 1230, 1231, 1232, 1233, 1234, 1235, 1236, 1237, 1238, 1239, 1240, 1241, 1242, 1243, 1244, 1245, 1246, 1247, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255
      },
    },
  }};

  for (size_t i = 0; i < sizeof(TESTS)/sizeof(TESTS[0]); i++) {
    // sample polynomial from NTT
    poly_t got = TESTS[i].a;
    poly_sub(&got, &(TESTS[i].b));

    // check for expected value
    if (memcmp(&got, &TESTS[i].exp, sizeof(poly_t))) {
      fprintf(stderr, "test_poly_sub(\"%s\") failed, got:\n", TESTS[i].name);
      poly_write(stderr, &got);
      fprintf(stderr, "\nexp:\n");
      poly_write(stderr, &(TESTS[i].exp));
      fprintf(stderr, "\n");
    }
  }
}

static void test_poly_mul(void) {
  static const struct {
    const char *name; // test name
    const poly_t a, b, // operands (not in NTT)
                 exp; // expected result
  } TESTS[] = {{
    .name = "1 * 1",
    .a = {
      .cs = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      },
    },

    .b = {
      .cs = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      },
    },

    .exp = {
      .cs = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      },
    },
  }, {
    .name = "x * x",
    .a = {
      .cs = {
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      },
    },

    .b = {
      .cs = {
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      },
    },

    .exp = {
      .cs = {
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      },
    },
  }};

  for (size_t i = 0; i < sizeof(TESTS)/sizeof(TESTS[0]); i++) {
    poly_t a = TESTS[i].a, b = TESTS[i].b, got = { 0 };

    // convert a and b ntt
    poly_ntt(&a);
    poly_ntt(&b);

    // multiply a and b, store product in got
    poly_mul(&got, &a, &b);

    // calculate inverse ntt of got
    poly_inv_ntt(&got);

    // check for expected value
    if (memcmp(&got, &TESTS[i].exp, sizeof(poly_t))) {
      fprintf(stderr, "test_poly_mul(\"%s\") failed, got:\n", TESTS[i].name);
      poly_write(stderr, &got);
      fprintf(stderr, "\nexp:\n");
      poly_write(stderr, &(TESTS[i].exp));
      fprintf(stderr, "\n");
    }
  }
}

int main(void) {
  test_poly_ntt_roundtrip();
  test_poly_sample_ntt();
  test_poly_add();
  test_poly_sub();
  test_poly_mul();
}
#endif // TEST_FIPS203
