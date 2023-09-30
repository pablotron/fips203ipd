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
static const uint16_t MUL_LUT[] = {
  1, // n = 0, 2*bitrev(0)+1 = 1, (17**1)%3329) = 1
  1729, // n = 1, 2*bitrev(1)+1 = 129, (17**129)%3329) = 1729
  2580, // n = 2, 2*bitrev(2)+1 = 65, (17**65)%3329) = 2580
  3289, // n = 3, 2*bitrev(3)+1 = 193, (17**193)%3329) = 3289
  2642, // n = 4, 2*bitrev(4)+1 = 33, (17**33)%3329) = 2642
  630, // n = 5, 2*bitrev(5)+1 = 161, (17**161)%3329) = 630
  1897, // n = 6, 2*bitrev(6)+1 = 97, (17**97)%3329) = 1897
  848, // n = 7, 2*bitrev(7)+1 = 225, (17**225)%3329) = 848
  1062, // n = 8, 2*bitrev(8)+1 = 17, (17**17)%3329) = 1062
  1919, // n = 9, 2*bitrev(9)+1 = 145, (17**145)%3329) = 1919
  193, // n = 10, 2*bitrev(10)+1 = 81, (17**81)%3329) = 193
  797, // n = 11, 2*bitrev(11)+1 = 209, (17**209)%3329) = 797
  2786, // n = 12, 2*bitrev(12)+1 = 49, (17**49)%3329) = 2786
  3260, // n = 13, 2*bitrev(13)+1 = 177, (17**177)%3329) = 3260
  569, // n = 14, 2*bitrev(14)+1 = 113, (17**113)%3329) = 569
  1746, // n = 15, 2*bitrev(15)+1 = 241, (17**241)%3329) = 1746
  296, // n = 16, 2*bitrev(16)+1 = 9, (17**9)%3329) = 296
  2447, // n = 17, 2*bitrev(17)+1 = 137, (17**137)%3329) = 2447
  1339, // n = 18, 2*bitrev(18)+1 = 73, (17**73)%3329) = 1339
  1476, // n = 19, 2*bitrev(19)+1 = 201, (17**201)%3329) = 1476
  3046, // n = 20, 2*bitrev(20)+1 = 41, (17**41)%3329) = 3046
  56, // n = 21, 2*bitrev(21)+1 = 169, (17**169)%3329) = 56
  2240, // n = 22, 2*bitrev(22)+1 = 105, (17**105)%3329) = 2240
  1333, // n = 23, 2*bitrev(23)+1 = 233, (17**233)%3329) = 1333
  1426, // n = 24, 2*bitrev(24)+1 = 25, (17**25)%3329) = 1426
  2094, // n = 25, 2*bitrev(25)+1 = 153, (17**153)%3329) = 2094
  535, // n = 26, 2*bitrev(26)+1 = 89, (17**89)%3329) = 535
  2882, // n = 27, 2*bitrev(27)+1 = 217, (17**217)%3329) = 2882
  2393, // n = 28, 2*bitrev(28)+1 = 57, (17**57)%3329) = 2393
  2879, // n = 29, 2*bitrev(29)+1 = 185, (17**185)%3329) = 2879
  1974, // n = 30, 2*bitrev(30)+1 = 121, (17**121)%3329) = 1974
  821, // n = 31, 2*bitrev(31)+1 = 249, (17**249)%3329) = 821
  289, // n = 32, 2*bitrev(32)+1 = 5, (17**5)%3329) = 289
  331, // n = 33, 2*bitrev(33)+1 = 133, (17**133)%3329) = 331
  3253, // n = 34, 2*bitrev(34)+1 = 69, (17**69)%3329) = 3253
  1756, // n = 35, 2*bitrev(35)+1 = 197, (17**197)%3329) = 1756
  1197, // n = 36, 2*bitrev(36)+1 = 37, (17**37)%3329) = 1197
  2304, // n = 37, 2*bitrev(37)+1 = 165, (17**165)%3329) = 2304
  2277, // n = 38, 2*bitrev(38)+1 = 101, (17**101)%3329) = 2277
  2055, // n = 39, 2*bitrev(39)+1 = 229, (17**229)%3329) = 2055
  650, // n = 40, 2*bitrev(40)+1 = 21, (17**21)%3329) = 650
  1977, // n = 41, 2*bitrev(41)+1 = 149, (17**149)%3329) = 1977
  2513, // n = 42, 2*bitrev(42)+1 = 85, (17**85)%3329) = 2513
  632, // n = 43, 2*bitrev(43)+1 = 213, (17**213)%3329) = 632
  2865, // n = 44, 2*bitrev(44)+1 = 53, (17**53)%3329) = 2865
  33, // n = 45, 2*bitrev(45)+1 = 181, (17**181)%3329) = 33
  1320, // n = 46, 2*bitrev(46)+1 = 117, (17**117)%3329) = 1320
  1915, // n = 47, 2*bitrev(47)+1 = 245, (17**245)%3329) = 1915
  2319, // n = 48, 2*bitrev(48)+1 = 13, (17**13)%3329) = 2319
  1435, // n = 49, 2*bitrev(49)+1 = 141, (17**141)%3329) = 1435
  807, // n = 50, 2*bitrev(50)+1 = 77, (17**77)%3329) = 807
  452, // n = 51, 2*bitrev(51)+1 = 205, (17**205)%3329) = 452
  1438, // n = 52, 2*bitrev(52)+1 = 45, (17**45)%3329) = 1438
  2868, // n = 53, 2*bitrev(53)+1 = 173, (17**173)%3329) = 2868
  1534, // n = 54, 2*bitrev(54)+1 = 109, (17**109)%3329) = 1534
  2402, // n = 55, 2*bitrev(55)+1 = 237, (17**237)%3329) = 2402
  2647, // n = 56, 2*bitrev(56)+1 = 29, (17**29)%3329) = 2647
  2617, // n = 57, 2*bitrev(57)+1 = 157, (17**157)%3329) = 2617
  1481, // n = 58, 2*bitrev(58)+1 = 93, (17**93)%3329) = 1481
  648, // n = 59, 2*bitrev(59)+1 = 221, (17**221)%3329) = 648
  2474, // n = 60, 2*bitrev(60)+1 = 61, (17**61)%3329) = 2474
  3110, // n = 61, 2*bitrev(61)+1 = 189, (17**189)%3329) = 3110
  1227, // n = 62, 2*bitrev(62)+1 = 125, (17**125)%3329) = 1227
  910, // n = 63, 2*bitrev(63)+1 = 253, (17**253)%3329) = 910
  17, // n = 64, 2*bitrev(64)+1 = 3, (17**3)%3329) = 17
  2761, // n = 65, 2*bitrev(65)+1 = 131, (17**131)%3329) = 2761
  583, // n = 66, 2*bitrev(66)+1 = 67, (17**67)%3329) = 583
  2649, // n = 67, 2*bitrev(67)+1 = 195, (17**195)%3329) = 2649
  1637, // n = 68, 2*bitrev(68)+1 = 35, (17**35)%3329) = 1637
  723, // n = 69, 2*bitrev(69)+1 = 163, (17**163)%3329) = 723
  2288, // n = 70, 2*bitrev(70)+1 = 99, (17**99)%3329) = 2288
  1100, // n = 71, 2*bitrev(71)+1 = 227, (17**227)%3329) = 1100
  1409, // n = 72, 2*bitrev(72)+1 = 19, (17**19)%3329) = 1409
  2662, // n = 73, 2*bitrev(73)+1 = 147, (17**147)%3329) = 2662
  3281, // n = 74, 2*bitrev(74)+1 = 83, (17**83)%3329) = 3281
  233, // n = 75, 2*bitrev(75)+1 = 211, (17**211)%3329) = 233
  756, // n = 76, 2*bitrev(76)+1 = 51, (17**51)%3329) = 756
  2156, // n = 77, 2*bitrev(77)+1 = 179, (17**179)%3329) = 2156
  3015, // n = 78, 2*bitrev(78)+1 = 115, (17**115)%3329) = 3015
  3050, // n = 79, 2*bitrev(79)+1 = 243, (17**243)%3329) = 3050
  1703, // n = 80, 2*bitrev(80)+1 = 11, (17**11)%3329) = 1703
  1651, // n = 81, 2*bitrev(81)+1 = 139, (17**139)%3329) = 1651
  2789, // n = 82, 2*bitrev(82)+1 = 75, (17**75)%3329) = 2789
  1789, // n = 83, 2*bitrev(83)+1 = 203, (17**203)%3329) = 1789
  1847, // n = 84, 2*bitrev(84)+1 = 43, (17**43)%3329) = 1847
  952, // n = 85, 2*bitrev(85)+1 = 171, (17**171)%3329) = 952
  1461, // n = 86, 2*bitrev(86)+1 = 107, (17**107)%3329) = 1461
  2687, // n = 87, 2*bitrev(87)+1 = 235, (17**235)%3329) = 2687
  939, // n = 88, 2*bitrev(88)+1 = 27, (17**27)%3329) = 939
  2308, // n = 89, 2*bitrev(89)+1 = 155, (17**155)%3329) = 2308
  2437, // n = 90, 2*bitrev(90)+1 = 91, (17**91)%3329) = 2437
  2388, // n = 91, 2*bitrev(91)+1 = 219, (17**219)%3329) = 2388
  733, // n = 92, 2*bitrev(92)+1 = 59, (17**59)%3329) = 733
  2337, // n = 93, 2*bitrev(93)+1 = 187, (17**187)%3329) = 2337
  268, // n = 94, 2*bitrev(94)+1 = 123, (17**123)%3329) = 268
  641, // n = 95, 2*bitrev(95)+1 = 251, (17**251)%3329) = 641
  1584, // n = 96, 2*bitrev(96)+1 = 7, (17**7)%3329) = 1584
  2298, // n = 97, 2*bitrev(97)+1 = 135, (17**135)%3329) = 2298
  2037, // n = 98, 2*bitrev(98)+1 = 71, (17**71)%3329) = 2037
  3220, // n = 99, 2*bitrev(99)+1 = 199, (17**199)%3329) = 3220
  375, // n = 100, 2*bitrev(100)+1 = 39, (17**39)%3329) = 375
  2549, // n = 101, 2*bitrev(101)+1 = 167, (17**167)%3329) = 2549
  2090, // n = 102, 2*bitrev(102)+1 = 103, (17**103)%3329) = 2090
  1645, // n = 103, 2*bitrev(103)+1 = 231, (17**231)%3329) = 1645
  1063, // n = 104, 2*bitrev(104)+1 = 23, (17**23)%3329) = 1063
  319, // n = 105, 2*bitrev(105)+1 = 151, (17**151)%3329) = 319
  2773, // n = 106, 2*bitrev(106)+1 = 87, (17**87)%3329) = 2773
  757, // n = 107, 2*bitrev(107)+1 = 215, (17**215)%3329) = 757
  2099, // n = 108, 2*bitrev(108)+1 = 55, (17**55)%3329) = 2099
  561, // n = 109, 2*bitrev(109)+1 = 183, (17**183)%3329) = 561
  2466, // n = 110, 2*bitrev(110)+1 = 119, (17**119)%3329) = 2466
  2594, // n = 111, 2*bitrev(111)+1 = 247, (17**247)%3329) = 2594
  2804, // n = 112, 2*bitrev(112)+1 = 15, (17**15)%3329) = 2804
  1092, // n = 113, 2*bitrev(113)+1 = 143, (17**143)%3329) = 1092
  403, // n = 114, 2*bitrev(114)+1 = 79, (17**79)%3329) = 403
  1026, // n = 115, 2*bitrev(115)+1 = 207, (17**207)%3329) = 1026
  1143, // n = 116, 2*bitrev(116)+1 = 47, (17**47)%3329) = 1143
  2150, // n = 117, 2*bitrev(117)+1 = 175, (17**175)%3329) = 2150
  2775, // n = 118, 2*bitrev(118)+1 = 111, (17**111)%3329) = 2775
  886, // n = 119, 2*bitrev(119)+1 = 239, (17**239)%3329) = 886
  1722, // n = 120, 2*bitrev(120)+1 = 31, (17**31)%3329) = 1722
  1212, // n = 121, 2*bitrev(121)+1 = 159, (17**159)%3329) = 1212
  1874, // n = 122, 2*bitrev(122)+1 = 95, (17**95)%3329) = 1874
  1029, // n = 123, 2*bitrev(123)+1 = 223, (17**223)%3329) = 1029
  2110, // n = 124, 2*bitrev(124)+1 = 63, (17**63)%3329) = 2110
  2935, // n = 125, 2*bitrev(125)+1 = 191, (17**191)%3329) = 2935
  885, // n = 126, 2*bitrev(126)+1 = 127, (17**127)%3329) = 885
  2154, // n = 127, 2*bitrev(127)+1 = 255, (17**255)%3329) = 2154
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
    const uint16_t d1 = ((uint16_t) ds[0]) + (((uint16_t) (ds[1] & 0xF)) << 4),
                   d2 = ((uint16_t) ds[1] >> 4) + (((uint16_t) ds[2]) << 4);

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
 * Initialize shake256 XOF as a PRF with given 32-byte value `s` and 1
 * byte value `b`, then read `len` bytes of data from the PRF into the
 * buffer pointed to by `out`.
 *
 * @param[in] s 32-byte buffer.
 * @param[in] b 1 byte value.
 * @param[out] out Output buffer of length `len`.
 * @param[in] len Output buffer length.
 */
static inline void prf(const uint8_t s[static 32], const uint8_t b, uint8_t * const out, const size_t len) {
  uint8_t buf[33] = { 0 };
  memcpy(buf, s, 32); // populate buf with seed
  buf[32] = b;
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
        p->cs[j + len] = (zeta * (p->cs[j] + (Q - t))) % Q;
      }
    }
  }

  for (size_t i = 0; i < 256; i++) {
    p->cs[i] = (p->cs[i] * 3308) % Q;
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
    out[3 * i + 1] = (uint8_t) ((a0 >> 4) | ((a1 & 0xf) << 4));
    out[3 * i + 2] = (uint8_t) (a1 >> 4);
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

static void test_poly_ntt(void) {
  static const struct {
    const char *name;
    const poly_t poly;
  } TESTS[] = {{
    .name = "test",
    .poly = {
      .cs = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
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
    if (!memcmp(&got, &TESTS[i].poly, sizeof(poly_t))) {
      fprintf(stderr, "test_poly_ntt(\"%s\") failed, got:\n", TESTS[i].name);
      poly_write(stderr, &got);
      fprintf(stderr, "exp:\n");
      poly_write(stderr, &(TESTS[i].poly));
      fprintf(stderr, "\n");
    }
  }
}

int main(void) {
  test_poly_ntt();
}
#endif // TEST_FIPS203
