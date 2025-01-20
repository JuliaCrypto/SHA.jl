using SHA, Test

include("constants.jl")

function describe_hash(T::Type{S}) where {S <: SHA.SHA_CTX}
    if T <: SHA.SHA1_CTX return "SHA1" end
    if T <: SHA.SHA2_CTX return "SHA2-$(SHA.digestlen(T)*8)" end
    if T <: SHA.SHA3_CTX return "SHA3-$(SHA.digestlen(T)*8)" end
end

@debug("Loaded hash types: $(join(sort([describe_hash(t[2]) for t in sha_types]), ", ", " and "))")

@testset "Hashing" begin
    # First, test processing the data in one go
    @testset "Complete" begin
        for idx in 1:length(data)
            @testset "$(data_desc[idx])" begin
                for sha_idx in 1:length(sha_funcs)
                    sha_func = sha_funcs[sha_idx]
                    hash = bytes2hex(sha_func(deepcopy(data[idx])))
                    @test hash == answers[sha_func][idx]

                    # Test sha_(::AbstractString)
                    if data[idx] isa String
                        sub_str = deepcopy(data[idx]) |> SubString
                        @test bytes2hex(sha_func(sub_str)) == answers[sha_func][idx]
                    end
                end
            end
        end
    end

    # Do another test on the "so many a's" data where we chunk up the data into
    # two chunks, (sized appropriately to AVOID overflow from one update to another)
    # in order to test multiple update!() calls
    @testset "Chunked Properly" begin
        for sha_idx in 1:length(sha_funcs)
            ctx = sha_types[sha_funcs[sha_idx]]()
            SHA.update!(ctx, so_many_as_array[1:2*SHA.blocklen(typeof(ctx))])
            SHA.update!(ctx, so_many_as_array[2*SHA.blocklen(typeof(ctx))+1:end])
            hash = bytes2hex(SHA.digest!(ctx))
            @test hash == answers[sha_funcs[sha_idx]][end]
        end
    end

    # Do another test on the "so many a's" data where we chunk up the data into
    # three chunks, (sized appropriately to CAUSE overflow from one update to another)
    # in order to test multiple update!() calls as well as the overflow codepaths
    @testset "Chunked clumsily" begin
        for sha_idx in 1:length(sha_funcs)
            ctx = sha_types[sha_funcs[sha_idx]]()

            # Get indices awkwardly placed for the blocklength of this hash type
            idx0 = round(Int, 0.3*SHA.blocklen(typeof(ctx)))
            idx1 = round(Int, 1.7*SHA.blocklen(typeof(ctx)))
            idx2 = round(Int, 2.6*SHA.blocklen(typeof(ctx)))

            # Feed data in according to our dastardly blocking scheme
            SHA.update!(ctx, so_many_as_array[0      + 1:1*idx0])
            SHA.update!(ctx, so_many_as_array[1*idx0 + 1:2*idx0])
            SHA.update!(ctx, so_many_as_array[2*idx0 + 1:3*idx0])
            SHA.update!(ctx, so_many_as_array[3*idx0 + 1:4*idx0])
            SHA.update!(ctx, so_many_as_array[4*idx0 + 1:idx1])
            SHA.update!(ctx, so_many_as_array[idx1 + 1:idx2])
            SHA.update!(ctx, so_many_as_array[idx2 + 1:end])

            # Ensure the hash is the appropriate one
            hash = bytes2hex(SHA.digest!(ctx))
            @test hash == answers[sha_funcs[sha_idx]][end]
        end
    end

    # Test that the hash states cannot be updated after having been finalized,
    # but can still return the same digest
    @testset "Reuse" begin
        for sha_idx in 1:length(sha_funcs)
            ctx = sha_types[sha_funcs[sha_idx]]()
            update!(ctx, codeunits("abracadabra"))
            hash1 = digest!(ctx)

            # Cannot update after having been digested
            @test_throws Exception update!(ctx, codeunits("abc"))

            # But will still return the same digest twice
            hash2 = digest!(ctx)
            @test hash1 == hash2
        end
    end
end

@testset "SHA-512/t" begin
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
    @test sha2_512_224("abc") |> bytes2hex ==
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    @test sha2_512_224("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") |> bytes2hex ==
        "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
    @test sha2_512_256("abc") |> bytes2hex ==
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    @test sha2_512_256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") |> bytes2hex ==
        "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
end

@testset "SHA3" begin
    @test sha3_512("0" ^ 70) |> bytes2hex ==
        "1ec3e5ebb442c09e7ab7a1ee18edfa1a9ec771ad243e3e3d65cad1730416109a0890e29f9314babd7ab018a246b2f9639af29ee09aec2352a2f94dc12a2f6109"
    # test `digest!` branch: @assert  usedspace == blocklen(T) - 1
    @test sha3_512("0" ^ 71) |> bytes2hex ==
        "2bdaca04f78ae216331557358d124c0b79305735e5a65fa91a8d6504c92fe1a780ee992a5f0233dad0b79875333a40d1c26d435684442492ad1e3166ef19809b"
    @test sha3_512("0" ^ 72) |> bytes2hex ==
        "69eb8ccde4eec57d5e78512bf29081dc15d3ca650d5bf15cc9c0dfd7d7c477c067504fb99c7c787df248a9897cbeaeafeae563e855205660363dd700e1d43eee"
end

@testset "HMAC" begin
    # test hmac correctness using the examples from Wikipedia:
    # https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Examples
    for (key, msg, fun, hash) in hmac_data
        digest = bytes2hex(fun(Vector{UInt8}(key), Vector{UInt8}(msg)))
        @test digest == hash
        digest = bytes2hex(fun(Vector{UInt8}(key), IOBuffer(msg)))
        @test digest == hash
        digest = bytes2hex(fun(Vector{UInt8}(key), SubString(msg)))
        @test digest == hash
    end

    # help function for test: only accept `HMAC_CTX{SHA2_256_CTX}`
    Base.:(==)(x::SHA2_256_CTX, y::SHA2_256_CTX) =
        x.state==y.state && x.bytecount==y.bytecount && x.buffer==y.buffer
    Base.:(==)(x::HMAC_CTX{SHA2_256_CTX}, y::HMAC_CTX{SHA2_256_CTX}) =
        x.outer==y.outer && x.context==y.context

    # Test if branch in `HMAC_CTX` constructor: 
    key0 = sha256(zeros(UInt8, 128))
    key = zeros(UInt8, 128)
    blocksize = 64
    # test with looong key
    @assert length(key) > blocksize

    s0 = HMAC_CTX(SHA2_256_CTX(), key0, blocksize)
    s1 = HMAC_CTX(SHA2_256_CTX(), key, blocksize)
    @test s0 == s1
end

replstr(x) = sprint((io, x) -> show(IOContext(io, :limit => true), MIME("text/plain"), x), x)
@testset "REPL" begin
    for idx in 1:length(ctxs)
        @test typeof(copy(ctxs[idx]())) == typeof(ctxs[idx]())
        @test replstr(ctxs[idx]()) == shws[idx]
    end
end

@testset "Type-checking" begin
    for f in sha_funcs
        @test_throws MethodError f(UInt32[0x23467, 0x324775])
    end
end

@testset "codecov" begin
    # Table 3: Input block sizes for HMAC
    #   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    #        SHA3-224 -256 -384 -512
    block_size = [144, 136, 104, 72]
    byte_count = 2 * sizeof(SHA.state_type(SHA.SHA3_CTX))
    sha3_types = [SHA.SHA3_224_CTX, SHA.SHA3_256_CTX, SHA.SHA3_384_CTX, SHA.SHA3_512_CTX]
    @test [ SHA.short_blocklen(T) for T in sha3_types ] == (block_size .- byte_count)
end

@testset "SHAKE" begin
    # test some official testvectors from https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing
    @testset "shake128" begin
        for (k,v) in SHA128test
            @test SHA.shake128(hex2bytes(k[1]),k[2]) == hex2bytes(v)
        end
        @test SHA.shake128(b"",UInt(16)) == hex2bytes("7f9c2ba4e88f827d616045507605853e")
        @test SHA.shake128(codeunits("0" ^ 167), UInt(32)) == hex2bytes("ff60b0516fb8a3d4032900976e98b5595f57e9d4a88a0e37f7cc5adfa3c47da2")
    end

    @testset "shake256" begin
        for (k,v) in SHA256test
            @test SHA.shake256(hex2bytes(k[1]),k[2]) == hex2bytes(v)
        end
        @test SHA.shake256(b"",UInt(32)) == hex2bytes("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        @test SHA.shake256(codeunits("0"^135),UInt(32)) == hex2bytes("ab11f61b5085a108a58670a66738ea7a8d8ce23b7c57d64de83eaafb10923cf8")
    end
end
