using SHA, Test

include("constants.jl")

function describe_hash(T::Type{S}) where {S <: SHA.SHA_CTX}
    if T <: SHA.SHA1_CTX return "SHA1" end
    if T <: SHA.SHA2_CTX return "SHA2-$(SHA.digestlen(T)*8)" end
    if T <: SHA.SHA3_CTX return "SHA3-$(SHA.digestlen(T)*8)" end
end

@info("Loaded hash types: $(join(sort([describe_hash(t[2]) for t in sha_types]), ", ", " and "))")

@testset "Hashing" begin
    # First, test processing the data in one go
    @testset "Complete" begin
        for idx in 1:length(data)
            @testset "$(data_desc[idx])" begin
                for sha_idx in 1:length(sha_funcs)
                    sha_func = sha_funcs[sha_idx]
                    hash = bytes2hex(sha_func(deepcopy(data[idx])))
                    @test hash == answers[sha_func][idx]
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
end

@testset "SHA3" begin
    @test sha3_512("0" ^ 70) |> bytes2hex ==
        "1ec3e5ebb442c09e7ab7a1ee18edfa1a9ec771ad243e3e3d65cad1730416109a0890e29f9314babd7ab018a246b2f9639af29ee09aec2352a2f94dc12a2f6109"
    # test `digest!` branch: @assert  usedspace == blocklen(T) - 1
    @test sha3_512("0" ^ 71) |> bytes2hex ==
        "e6bb5d7cdde31df695c20516581127d9dab6e8d6c5196203d96a55251ce886b4824538baeaa519add156fd61633fec1ecffcc3e5d6c5a6d5da0f1c4d4e6f405e"
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
