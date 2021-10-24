# NIST CAVS —— Cryptographic Algorithm Validation Program
# Copyrights:   https://www.nist.gov/oism/copyrights
# Check `cavs.jl` for more information


# Note: The original CAVS test set contains the 100 checkpoints.
#   The following simplified test set contains only 5 checkpoints (0, 1, 19, 59, 99).

# ---- SHA-1/2/3 test vectors
SHA1_CAVS_VEC = [
#   (COUNT, MD)
    (0, "11f5c38b4479d4ad55cb69fadf62de0b036d5163")
    (1, "5c26de848c21586bec36995809cb02d3677423d9")
    (19, "23baee80eee052f3263ac26dd12ea6504a5bd234")
    (59, "b8b3cd6ca1d5b5610e43212f8df75211aaddcf96")
    (99, "01b7be5b70ef64843a03fdbb3b247a6278d2cbe1")
]

SHA2_224_CAVS_VEC = [
    (0, "cd94d7da13c030208b2d0d78fcfe9ea22fa8906df66aa9a1f42afa70")
    (1, "555846e884633639565d5e0c01dd93ba58edb01ee18e68ccca28f7b8")
    (19, "18751a765f3b06fc2c9a1888d4bb78b2d2226799a54dba72b5429f25")
    (59, "3998a213e392978a38016545a59bd435180da66d2b3da373088f406a")
    (99, "27033d2d89329ba9d2a39c0292552a5f1f945c115d5abf2064e93754")
]

SHA2_256_CAVS_VEC = [
    (0, "e93c330ae5447738c8aa85d71a6c80f2a58381d05872d26bdd39f1fcd4f2b788")
    (1, "2e78f8c8772ea7c9331d41ed3f9cdf27d8f514a99342ee766ee3b8b0d0b121c0")
    (19, "52519e6319505df7a9aa83778618ec10b78c5771bac50e8d3f59bc815dabfb1f")
    (59, "ae5a4fdc779d808ba898966c8c14a6c9894107ef3e1d680f6ae37e95cb7e1b67")
    (99, "6a912ba4188391a78e6f13d88ed2d14e13afce9db6f7dcbf4a48c24f3db02778")
]

SHA2_384_CAVS_VEC = [
    (0, "e81b86c49a38feddfd185f71ca7da6732a053ed4a2640d52d27f53f9f76422650b0e93645301ac99f8295d6f820f1035")
    (1, "1d6bd21713bffd50946a10c39a7742d740e8f271f0c8f643d4c95375094fd9bf29d89ee61a76053f22e44a4b058a64ed")
    (19, "b9158943803c47678fefafa91c98966aa3dc1fd96f4e86cfdde7ca879dbf9fa9f54b1988a53376f7005df7fd87b1396b")
    (59, "14e1b1733b16899c4046a604f8e1e777d55649c5357d7d9e3d7a1c395b6275aecf733a598de1d0bfd7eeaa9ecbd7d1e7")
    (99, "ccde4359f23e64579c5c0380df837ee950928aa82937a2d2ed33d216e707c46d847efa5ca52dcbda551145e164fbd594")
]

SHA2_512_CAVS_VEC = [
    (0, "ada69add0071b794463c8806a177326735fa624b68ab7bcab2388b9276c036e4eaaff87333e83c81c0bca0359d4aeebcbcfd314c0630e0c2af68c1fb19cc470e")
    (1, "ef219b37c24ae507a2b2b26d1add51b31fb5327eb8c3b19b882fe38049433dbeccd63b3d5b99ba2398920bcefb8aca98cd28a1ee5d2aaf139ce58a15d71b06b4")
    (19, "3d40ccd9cc445bbecca9227c67fe455d89e0b7c1c858d32f30e2b544ca9a5a606535aea2e59fec6ec4d1ba898cc4338c6eadef9c0884bcf56aca2f481a2d7d3e")
    (59, "2f3d5c5f990bf615d5e8b396ccbd0337da39fad09b059f955a431db76a9dc720dffc4e02c0be397c7e0463799cd75fd6ab7c52bec66c8df5ef0d47e14a4c5927")
    (99, "4aa7dad74eb51d09a6ae7735c4b795b078f51c314f14f42a0d63071e13bdc5fd9f51612e77b36d44567502a3b5eb66c609ec017e51d8df93e58d1a44f3c1e375")
]

# SHA2_512_224_CAVS_VEC = [
#     (0, "")
#     (1, "")
#     (19, "")
#     (59, "")
#     (99, "")
# ]

# SHA2_512_256_CAVS_VEC = [
#     (0, "")
#     (1, "")
#     (19, "")
#     (59, "")
#     (99, "")
# ]

SHA3_224_CAVS_VEC = [
    (0, "90080c037bda5fafcada98e8afda62b10ffb5781b97f6e7aa3ded6e6")
    (1, "b56de7b4b405b0bdf23ed9c4593956cb4231846f278cd8d8699ab7c0")
    (19, "76a224d6016e5c010b08e95e58ea013145b776056b12a74786c6ec2b")
    (59, "b6e3132fba32608d03abce8a9e83613a9f40b0cc43fc730ea627b9ba")
    (99, "91defbe230b514d7db13d915a82368d32d48f55db31d16e3ae7fbbd0")
]

SHA3_256_CAVS_VEC = [
    (0, "225cbac2be6f329d94228c5360a1c177bc495a761c442a1771b1d18555c309a5")
    (1, "96d364a1b1ced3dbbce6380093fb1ac77221abcee30faf16546ffad8fe1eef8c")
    (19, "d79a6f3dde5e053f342a2a2a9f844ddac71e5ff468a0d3276c81bd8126b3ee17")
    (59, "c00ce2788f5ab3d14a492240ea54d05bac108353a2203436d3e0701c1b088262")
    (99, "456f2ed7f5433bb4e56d7780a21a953e95d6a5eb53bb4c974c57a90e677f3197")
]

SHA3_384_CAVS_VEC = [
    (0, "b2d4e10214bd7991e3a3e4772f5c7b390178e20c3ff882648a891e44b9d309d91bf5fab74c0bc155a7fac972a9b128a2")
    (1, "608db3176176effb7b7cceb8962bffc67584cc9e9860752f6644c7810cc83f4fdefa108bcf308d4137265fbb1ecf10fb")
    (19, "4f31053aa710a9376fa2a410e3458c1b4d9005c66ae01f41c093996f9a8b5c6885467acd9ad4b4bbbe1fa32d24ace547")
    (59, "bab50ad626ec56d8dbe9a9318a2fcb2359d0accd9499bd76a8db33922503f40f3b0e9a43af68d537bfac341b343d21d8")
    (99, "02c9babd4add11a5f23c1808f72e3dc8325cedc31d28213a04d999dac8f46b866f84ba3dbfbcf1a863cc54d808ffadca")
]

SHA3_512_CAVS_VEC = [
    (0, "83dd81285c36d86dde72631a1a1e0d9c12b0e2842d499a63b00de87f11839565b21d9416f154b72034b7fcd41d2f1d9eac184eec823547772826ed90c53d856e")
    (1, "5c37bb6fe060007ce3fca1e6d01ed1bdd6e737f043a2929548cf1b08224a193e03c7314be44a496c8ecaf8a7458770f59cd27336a38ffa40588539572ecb946f")
    (19, "099d3e5e4fd60468274b7f486f379487786596ac216bde7f095ef4a1617e02223d404cee0dc801175c3dbd02947b37e3a26628b7573f92a6ae26e34eec6800d0")
    (59, "1c8d7b5a951258e4f2f56a664c79b4b921f2296d360b6cc91eeb5cce08180d6d1ff0296db5ad9a7a4c2f69a5c2fcafa550961115d87713a7da3ccb619ec79733")
    (99, "760824a439b0681fcd5d22f8467d927a764febc457fd1eb62584ca82b00e1a07905a0117a955041892d2c9d849c096067ed2893aca5c841f8aa32dabe642bc82")
]


# ---- CAVS test metadata
"""
Metadata and test vectors came from:
    SHA*Monte.rsp (CAVS 11.1)
    FIPS 180-4 - SHA Test Vectors for Hashing Byte-Oriented Messages
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
"""
CAVS_TESTSET_12 = Dict(
    # SHA-1
    sha1 => (
        # test name
        name = "SHA-1 Monte",
        # test seed
        seed = "dd4df644eaf3d85bace2b21accaa22b28821f5cd",
        # seed length in byte
        seed_len = 20,
        # test vector array :: Vector{Tuple{Int64, String}}
        cavs_vec = SHA1_CAVS_VEC
    ),

    # SHA-2
    sha2_224 => (
        name = "SHA-224 Monte",
        seed = "ed2b70d575d9d0b4196ae84a03eed940057ea89cdd729b95b7d4e6a5",
        seed_len = 28,
        cavs_vec = SHA2_224_CAVS_VEC
    ),
    sha2_256 => (
        name = "SHA-256 Monte",
        seed = "6d1e72ad03ddeb5de891e572e2396f8da015d899ef0e79503152d6010a3fe691",
        seed_len = 32,
        cavs_vec = SHA2_256_CAVS_VEC
    ),
    sha2_384 => (
        name = "SHA-384 Monte",
        seed = "edff07255c71b54a9beae52cdfa083569a08be89949cbba73ddc8acf429359ca5e5be7a673633ca0d9709848f522a9df",
        seed_len = 48,
        cavs_vec = SHA2_384_CAVS_VEC
    ),
    sha2_512 => (
        name = "SHA-512 Monte",
        seed = "5c337de5caf35d18ed90b5cddfce001ca1b8ee8602f367e7c24ccca6f893802fb1aca7a3dae32dcd60800a59959bc540d63237876b799229ae71a2526fbc52cd",
        seed_len = 64,
        cavs_vec = SHA2_512_CAVS_VEC
    ),
    # sha2_512_224 => (
    #     name = "SHA-512/224 Monte",
    #     seed = "2e325bf8c98c0be54493d04c329e706343aebe4968fdd33b37da9c0a",
    #     seed_len = 28,
    #     cavs_vec = SHA2_512_224_CAVS_VEC
    # ),
    # sha2_512_256 => (
    #     name = "SHA-512/256 Monte",
    #     seed = "f41ece2613e4573915696b5adcd51ca328be3bf566a9ca99c9ceb0279c1cb0a7",
    #     seed_len = 32,
    #     cavs_vec = SHA2_512_256_CAVS_VEC
    # )
)


"""
Metadata and test vectors came from:
    SHA3_*Monte.rsp (CAVS 19.0)
    FIPS 202 - SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented Messages
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
"""
CAVS_TESTSET_3 = Dict(
    # SHA-3
    sha3_224 => (
        name = "SHA3-224 Monte",
        seed = "3a9415d401aeb8567e6f0ecee311f4f716b39e86045c8a51383db2b6",
        seed_len = 28,
        cavs_vec = SHA3_224_CAVS_VEC
    ),
    sha3_256 => (
        name = "SHA3-256 Monte",
        seed = "aa64f7245e2177c654eb4de360da8761a516fdc7578c3498c5e582e096b8730c",
        seed_len = 32,
        cavs_vec = SHA3_256_CAVS_VEC
    ),
    sha3_384 => (
        name = "SHA3-384 Monte",
        seed = "7a00791f6f65c21f1c97c58fa3c0520cfc85cd7e3d398cf01950819fa717195065a363e77d07753647cb0c130e9972ad",
        seed_len = 48,
        cavs_vec = SHA3_384_CAVS_VEC
    ),
    sha3_512 => (
        name = "SHA3-512 Monte",
        seed = "764a5511f00dbb0eaef2eb27ad58d35f74f563b88f789ff53f6cf3a47060c75ceb455444cd17b6d438c042e0483919d249f2fd372774647d2545cbfad20b4d31",
        seed_len = 64,
        cavs_vec = SHA3_512_CAVS_VEC
    )
)
