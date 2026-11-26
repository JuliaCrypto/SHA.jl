"""
    SHA

The SHA module provides hashing functionality for SHA1, SHA2 and SHA3 algorithms.

They are implemented as both pure functions for hashing single pieces of data,
or a stateful context which can be updated with the `update!` function and
finalized with `digest!`.

```julia-repl
julia> sha1(b"some data")
20-element Vector{UInt8}:
 0xba
 0xf3
    ⋮
 0xe3
 0x56


julia> ctx = SHA1_CTX()
SHA1 hash state

julia> update!(ctx, b"some data")
0x0000000000000009

julia> digest!(ctx)
20-element Vector{UInt8}:
 0xba
 0xf3
    ⋮
 0xe3
 0x56
"""
module SHA

# Export convenience functions, context types, update!() and digest!() functions
export sha1, SHA1_CTX, update!, digest!
export sha224, sha256, sha384, sha512
export sha2_224, sha2_256, sha2_384, sha2_512
export sha2_512_224, sha2_512_256
export sha3_224, sha3_256, sha3_384, sha3_512
export shake128, shake256
export SHA224_CTX, SHA256_CTX, SHA384_CTX, SHA512_CTX
export SHA2_224_CTX, SHA2_256_CTX, SHA2_384_CTX, SHA2_512_CTX
export SHA2_512_224_CTX, SHA2_512_256_CTX
export SHA3_224_CTX, SHA3_256_CTX, SHA3_384_CTX, SHA3_512_CTX
export SHAKE_128_CTX, SHAKE_256_CTX
export HMAC_CTX, hmac_sha1
export hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512
export hmac_sha2_224, hmac_sha2_256, hmac_sha2_384, hmac_sha2_512
export hmac_sha3_224, hmac_sha3_256, hmac_sha3_384, hmac_sha3_512

# data to be hashed:
"""
Union{AbstractVector{UInt8}, NTuple{N, UInt8} where N}
"""
const AbstractBytes = Union{AbstractVector{UInt8},NTuple{N,UInt8} where N}

# byte containers that support `pointer(data, i)` to contiguous memory
const ContiguousBytes = Union{DenseVector{UInt8},
                              Base.FastContiguousSubArray{UInt8,1,<:DenseVector{UInt8}},
                              Base.CodeUnits{UInt8,String}}

include("constants.jl")
include("types.jl")
include("base_functions.jl")
include("sha1.jl")

# Hardware acceleration of SHA-1 and SHA-256 (ARMv8 SHA1/SHA2, x86 SHA-NI), used if
# the CPU supports it. Requires Julia 1.10+; older versions use the software path.
@static if Sys.ARCH === :aarch64 && VERSION >= v"1.10"
    include("hw_aarch64.jl")
    const HAS_HW_IMPL = true
elseif Sys.ARCH === :x86_64 && VERSION >= v"1.10"
    include("hw_x86_64.jl")
    const HAS_HW_IMPL = true
else
    const HAS_HW_IMPL = false
    sha256_blocks_hw!(_, _, _) = error("unreachable")
    sha1_blocks_hw!(_, _, _) = error("unreachable")
end

# Availability must be determined in the running process (not when precompiling),
# since a package image may be loaded on a different CPU than it was built on.
# JULIA_SHA_DISABLE_HW=1 (or true/yes) forces the software implementation.
sha_hw_disabled() = Base.get_bool_env("JULIA_SHA_DISABLE_HW", false) === true
@static if !HAS_HW_IMPL
    sha_hw_available() = false
elseif isdefined(Base, :OncePerProcess)
    const SHA_HW = Base.OncePerProcess{Bool}() do
        !sha_hw_disabled() && detect_sha_hw()
    end
    sha_hw_available() = SHA_HW()
else # Julia 1.10 and 1.11
    # Lazily cached per process. A Ptr is used since Ptr values are saved as C_NULL in
    # package and system images, so a value cached while generating an image resets to
    # "not determined yet" when the image is loaded.
    # C_NULL = not determined yet, Ptr(1) = unavailable, Ptr(2) = available.
    # No lock is needed: threads racing on first use may each run the detection, but
    # they compute the same value, and a pointer-sized load or store cannot tear.
    const SHA_HW = Ref{Ptr{Cvoid}}(C_NULL)
    @inline function sha_hw_available()
        s = SHA_HW[]
        return s == C_NULL ? init_sha_hw() : s == Ptr{Cvoid}(2)
    end
    @noinline function init_sha_hw()
        hw = !sha_hw_disabled() && detect_sha_hw()
        SHA_HW[] = Ptr{Cvoid}(hw ? 2 : 1)
        return hw
    end
end

include("sha2.jl")
include("sha3.jl")
include("shake.jl")
include("common.jl")
include("hmac.jl")

# Create data types and convenience functions for each hash implemented
for (f, ctx) in [(:sha1, :SHA1_CTX),
                 (:sha224, :SHA224_CTX),
                 (:sha256, :SHA256_CTX),
                 (:sha384, :SHA384_CTX),
                 (:sha512, :SHA512_CTX),
                 (:sha2_224, :SHA2_224_CTX),
                 (:sha2_256, :SHA2_256_CTX),
                 (:sha2_384, :SHA2_384_CTX),
                 (:sha2_512, :SHA2_512_CTX),
                 (:sha2_512_224, :SHA2_512_224_CTX),
                 (:sha2_512_256, :SHA2_512_256_CTX),
                 (:sha3_224, :SHA3_224_CTX),
                 (:sha3_256, :SHA3_256_CTX),
                 (:sha3_384, :SHA3_384_CTX),
                 (:sha3_512, :SHA3_512_CTX)]
    g = Symbol(:hmac_, f)

    @eval begin
        # Our basic function is to process arrays of bytes
        """
            $($f)(data)

        Hash data using the `$($f)` algorithm and return the resulting digest.
        See also [`$($ctx)`](@ref).
        """
        function $f(data::AbstractBytes)
            ctx = $ctx()
            update!(ctx, data)
            return digest!(ctx)
        end

        """
            $($g)(key, data)

        Hash data using the `$($f)` algorithm using the passed key.
        See also [`HMAC_CTX`](@ref).
        """
        function $g(key::Vector{UInt8}, data::AbstractBytes)
            ctx = HMAC_CTX($ctx(), key)
            update!(ctx, data)
            return digest!(ctx)
        end

        # AbstractStrings are a pretty handy thing to be able to crunch through
        $f(str::AbstractString) = $f(String(str)) # always crunch UTF-8 repr
        $f(str::String) = $f(codeunits(str))
        $g(key::Vector{UInt8}, str::AbstractString) = $g(key, String(str))
        $g(key::Vector{UInt8}, str::String) = $g(key, codeunits(str))

        """
            $($f)(io::IO)

        Hash data from io using `$($f)` algorithm.
        """
        function $f(io::IO, chunk_size=4*1024)
            ctx = $ctx()
            buff = Vector{UInt8}(undef, chunk_size)
            while !eof(io)
                num_read = readbytes!(io, buff)
                update!(ctx, buff, num_read)
            end
            return digest!(ctx)
        end

        """
            $($g)(key, io::IO)

        Hash data from `io` with the passed key using `$($f)` algorithm.
        """
        function $g(key::Vector{UInt8}, io::IO, chunk_size=4*1024)
            ctx = HMAC_CTX($ctx(), key)
            buff = Vector{UInt8}(undef, chunk_size)
            while !eof(io)
                num_read = readbytes!(io, buff)
                update!(ctx, buff, num_read)
            end
            return digest!(ctx)
        end
    end
end

end #module SHA
