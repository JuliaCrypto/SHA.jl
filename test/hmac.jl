# NIST - Cryptographic Standards and Guidelines
# Examples with Intermediate Values
#   Message Authentication: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
# Copyrights:   https://www.nist.gov/oism/copyrights


NIST_EXAMPLE_VAL = [
    # ---- SHA1
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA1.pdf
    hmac_sha1 => [
        (key_len=64,  msg="Sample message for keylen=blocklen", mac="5FD596EE78D5553C8FF4E72D266DFD192366DA29"),
        (key_len=20,  msg="Sample message for keylen<blocklen", mac="4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807"),
        (key_len=100, msg="Sample message for keylen=blocklen", mac="2D51B2F7750E410584662E38F133435F4C4FD42A"),
        (key_len=49,  msg="Sample message for keylen<blocklen, with truncated tag", mac="FE3529565CD8E28C5FA79EAC9D8023B53B289D96")
    ],

    # ---- SHA2
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA224.pdf
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA256.pdf
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA384.pdf
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA512.pdf
    hmac_sha2_224 => [
        (key_len=64,  msg="Sample message for keylen=blocklen", mac="C7405E3AE058E8CD30B08B4140248581ED174CB34E1224BCC1EFC81B"),
        (key_len=28,  msg="Sample message for keylen<blocklen", mac="E3D249A8CFB67EF8B7A169E9A0A599714A2CECBA65999A51BEB8FBBE"),
        (key_len=100, msg="Sample message for keylen=blocklen", mac="91C52509E5AF8531601AE6230099D90BEF88AAEFB961F4080ABC014D"),
        (key_len=49,  msg="Sample message for keylen<blocklen, with truncated tag", mac="D522F1DF596CA4B4B1C23D27BDE067D6153BA9725FD5CDE0AF4A2A42")
    ],
    hmac_sha2_256 => [
        (key_len=64,  msg="Sample message for keylen=blocklen", mac="8BB9A1DB9806F20DF7F77B82138C7914D174D59E13DC4D0169C9057B133E1D62"),
        (key_len=32,  msg="Sample message for keylen<blocklen", mac="A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790"),
        (key_len=100, msg="Sample message for keylen=blocklen", mac="BDCCB6C72DDEADB500AE768386CB38CC41C63DBB0878DDB9C7A38A431B78378D"),
        (key_len=49,  msg="Sample message for keylen<blocklen, with truncated tag", mac="27A8B157839EFEAC98DF070B331D593618DDB985D403C0C786D23B5D132E57C7")
    ],
    hmac_sha2_384 => [
        (key_len=128, msg="Sample message for keylen=blocklen", mac="63C5DAA5E651847CA897C95814AB830BEDEDC7D25E83EEF9195CD45857A37F448947858F5AF50CC2B1B730DDF29671A9"),
        (key_len=48,  msg="Sample message for keylen<blocklen", mac="6EB242BDBB582CA17BEBFA481B1E23211464D2B7F8C20B9FF2201637B93646AF5AE9AC316E98DB45D9CAE773675EEED0"),
        (key_len=200, msg="Sample message for keylen=blocklen", mac="5B664436DF69B0CA22551231A3F0A3D5B4F97991713CFA84BFF4D0792EFF96C27DCCBBB6F79B65D548B40E8564CEF594"),
        (key_len=49,  msg="Sample message for keylen<blocklen, with truncated tag", mac="C48130D3DF703DD7CDAA56800DFBD2BA2458320E6E1F98FEC8AD9F57F43800DF3615CEB19AB648E1ECDD8C730AF95C8A")
    ],
    hmac_sha2_512 => [
        (key_len=128, msg="Sample message for keylen=blocklen", mac="FC25E240658CA785B7A811A8D3F7B4CA48CFA26A8A366BF2CD1F836B05FCB024BD36853081811D6CEA4216EBAD79DA1CFCB95EA4586B8A0CE356596A55FB1347"),
        (key_len=64,  msg="Sample message for keylen<blocklen", mac="FD44C18BDA0BB0A6CE0E82B031BF2818F6539BD56EC00BDC10A8A2D730B3634DE2545D639B0F2CF710D0692C72A1896F1F211C2B922D1A96C392E07E7EA9FEDC"),
        (key_len=200, msg="Sample message for keylen=blocklen", mac="D93EC8D2DE1AD2A9957CB9B83F14E76AD6B5E0CCE285079A127D3B14BCCB7AA7286D4AC0D4CE64215F2BC9E6870B33D97438BE4AAA20CDA5C5A912B48B8E27F3"),
        (key_len=49,  msg="Sample message for keylen<blocklen, with truncated tag", mac="00F3E9A77BB0F06DE15F160603E42B5028758808596664C03E1AB8FB2B0767780563AEDC644960D4F0C0C5D239F67A2A61B141E8C871F3D40DB2C605588DAB92")
    ],

    # ---- SHA3
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-224.pdf
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-256.pdf
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-384.pdf
    #   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-512.pdf
    hmac_sha3_224 => [
        (key_len=28,  msg="Sample message for keylen<blocklen", mac="332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04"),
        (key_len=144, msg="Sample message for keylen=blocklen", mac="d8b733bcf66c644a12323d564e24dcf3fc75f231f3b67968359100c7"),
        (key_len=172, msg="Sample message for keylen>blocklen", mac="078695eecc227c636ad31d063a15dd05a7e819a66ec6d8de1e193e59"),
        (key_len=28,  msg="Sample message for keylen<blocklen, with truncated tag", mac="8569c54cbb00a9b78ff1b391b0e5cd2fa5ec728550aa3979703305d4")
    ],
    hmac_sha3_256 => [
        (key_len=32,  msg="Sample message for keylen<blocklen", mac="4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205"),
        (key_len=136, msg="Sample message for keylen=blocklen", mac="68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa"),
        (key_len=168, msg="Sample message for keylen>blocklen", mac="9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258"),
        (key_len=32,  msg="Sample message for keylen<blocklen, with truncated tag", mac="c8dc7148d8c1423aa549105dafdf9cad2941471b5c62207088e56ccf2dd80545")
    ],
    hmac_sha3_384 => [
        (key_len=48,  msg="Sample message for keylen<blocklen", mac="d588a3c51f3f2d906e8298c1199aa8ff6296218127f6b38a90b6afe2c5617725bc99987f79b22a557b6520db710b7f42"),
        (key_len=104, msg="Sample message for keylen=blocklen", mac="a27d24b592e8c8cbf6d4ce6fc5bf62d8fc98bf2d486640d9eb8099e24047837f5f3bffbe92dcce90b4ed5b1e7e44fa90"),
        (key_len=152, msg="Sample message for keylen>blocklen", mac="e5ae4c739f455279368ebf36d4f5354c95aa184c899d3870e460ebc288ef1f9470053f73f7c6da2a71bcaec38ce7d6ac"),
        (key_len=48,  msg="Sample message for keylen<blocklen, with truncated tag", mac="25f4bf53606e91af79d24a4bb1fd6aecd44414a30c8ebb0ae09764c71aceefe8dfa72309e48152c98294be658a33836e")
    ],
    hmac_sha3_512 => [
        (key_len=64,  msg="Sample message for keylen<blocklen", mac="4efd629d6c71bf86162658f29943b1c308ce27cdfa6db0d9c3ce81763f9cbce5f7ebe9868031db1a8f8eb7b6b95e5c5e3f657a8996c86a2f6527e307f0213196"),
        (key_len=72,  msg="Sample message for keylen=blocklen", mac="544e257ea2a3e5ea19a590e6a24b724ce6327757723fe2751b75bf007d80f6b360744bf1b7a88ea585f9765b47911976d3191cf83c039f5ffab0d29cc9d9b6da"),
        (key_len=136, msg="Sample message for keylen>blocklen", mac="5f464f5e5b7848e3885e49b2c385f0694985d0e38966242dc4a5fe3fea4b37d46b65ceced5dcf59438dd840bab22269f0ba7febdb9fcf74602a35666b2a32915"),
        (key_len=64,  msg="Sample message for keylen<blocklen, with truncated tag", mac="7bb06d859257b25ce73ca700df34c5cbef5c898bac91029e0b27975d4e526a088f5e590ee736969f445643a58bee7ee0cbbbb2e14775584435d36ad0de6b9499")
    ]
]


function key_gen(len::Int)
    UnitRange{UInt8}(0, len-1) |> collect
end
