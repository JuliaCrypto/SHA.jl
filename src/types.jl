# Type hierarchy to aid in splitting up of SHA2 algorithms
# as SHA224/256 are similar, and SHA-384/512 are similar
abstract type SHA_CTX end
abstract type SHA2_CTX <: SHA_CTX end
abstract type SHA3_CTX <: SHA_CTX end
import Base: copy

# We derive SHA1_CTX straight from SHA_CTX since it doesn't have a
# family of types like SHA2 or SHA3 do
mutable struct SHA1_CTX <: SHA_CTX
    state::Vector{UInt32}
    bytecount::UInt64
    buffer::Vector{UInt8}
    W::Vector{UInt32}
    used::Bool
end

# SHA2 224/256/384/512-bit Context Structures
mutable struct SHA2_224_CTX <: SHA2_CTX
    state::Vector{UInt32}
    bytecount::UInt64
    buffer::Vector{UInt8}
    used::Bool
end

mutable struct SHA2_256_CTX <: SHA2_CTX
    state::Vector{UInt32}
    bytecount::UInt64
    buffer::Vector{UInt8}
    used::Bool
end

mutable struct SHA2_384_CTX <: SHA2_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end

mutable struct SHA2_512_CTX <: SHA2_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end

mutable struct SHA2_512_224_CTX <: SHA2_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end

mutable struct SHA2_512_256_CTX <: SHA2_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end


# Typealias common nicknames for SHA2 family of functions
const SHA224_CTX = SHA2_224_CTX
const SHA256_CTX = SHA2_256_CTX
const SHA384_CTX = SHA2_384_CTX
const SHA512_CTX = SHA2_512_CTX
const SHA512_224_CTX = SHA2_512_224_CTX
const SHA512_256_CTX = SHA2_512_256_CTX

# SHA3 224/256/384/512-bit context structures
mutable struct SHA3_224_CTX <: SHA3_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end
mutable struct SHA3_256_CTX <: SHA3_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end
mutable struct SHA3_384_CTX <: SHA3_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end
mutable struct SHA3_512_CTX <: SHA3_CTX
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end

# Define constants via functions so as not to bloat context objects.  Yay dispatch!

# Digest lengths for SHA1, SHA2 and SHA3.  This is easy to figure out from the typename
digestlen(::Type{SHA1_CTX}) = 20
digestlen(::Type{SHA2_224_CTX}) = 28
digestlen(::Type{SHA3_224_CTX}) = 28
digestlen(::Type{SHA2_256_CTX}) = 32
digestlen(::Type{SHA3_256_CTX}) = 32
digestlen(::Type{SHA2_384_CTX}) = 48
digestlen(::Type{SHA3_384_CTX}) = 48
digestlen(::Type{SHA2_512_CTX}) = 64
digestlen(::Type{SHA2_512_224_CTX}) = 28
digestlen(::Type{SHA2_512_256_CTX}) = 32
digestlen(::Type{SHA3_512_CTX}) = 64

# SHA1 and SHA2 have differing element types for the internal state objects
state_type(::Type{SHA1_CTX}) = UInt32
state_type(::Type{SHA2_224_CTX}) = UInt32
state_type(::Type{SHA2_256_CTX}) = UInt32
state_type(::Type{SHA2_384_CTX}) = UInt64
state_type(::Type{SHA2_512_CTX}) = UInt64
state_type(::Type{SHA2_512_224_CTX}) = UInt64
state_type(::Type{SHA2_512_256_CTX}) = UInt64
state_type(::Type{T}) where {T<:SHA3_CTX} = UInt64

# blocklen is the number of bytes of data processed by the transform!() function at once
blocklen(::Type{SHA1_CTX}) = UInt64(64)
blocklen(::Type{SHA2_224_CTX}) = UInt64(64)
blocklen(::Type{SHA2_256_CTX}) = UInt64(64)
blocklen(::Type{SHA2_384_CTX}) = UInt64(128)
blocklen(::Type{SHA2_512_CTX}) = UInt64(128)
blocklen(::Type{SHA2_512_224_CTX}) = UInt64(128)
blocklen(::Type{SHA2_512_256_CTX}) = UInt64(128)
blocklen(::Type{SHA3_224_CTX}) = UInt64(25*8 - 2*digestlen(SHA3_224_CTX))
blocklen(::Type{SHA3_256_CTX}) = UInt64(25*8 - 2*digestlen(SHA3_256_CTX))
blocklen(::Type{SHA3_384_CTX}) = UInt64(25*8 - 2*digestlen(SHA3_384_CTX))
blocklen(::Type{SHA3_512_CTX}) = UInt64(25*8 - 2*digestlen(SHA3_512_CTX))


# short_blocklen is the size of a block minus the width of bytecount
short_blocklen(::Type{T}) where {T<:SHA_CTX} = blocklen(T) - 2*sizeof(state_type(T))

# Once the "blocklen" methods are defined, we can define our outer constructors for SHA types:

"""
    SHA2_224_CTX()

Construct an empty SHA2_224 context.
"""
SHA2_224_CTX() = SHA2_224_CTX(copy(SHA2_224_initial_hash_value), 0, zeros(UInt8, blocklen(SHA2_224_CTX)), false)
"""
    SHA2_256_CTX()

Construct an empty SHA2_256 context.
"""
SHA2_256_CTX() = SHA2_256_CTX(copy(SHA2_256_initial_hash_value), 0, zeros(UInt8, blocklen(SHA2_256_CTX)), false)
"""
    SHA2_384()

Construct an empty SHA2_384 context.
"""
SHA2_384_CTX() = SHA2_384_CTX(copy(SHA2_384_initial_hash_value), 0, zeros(UInt8, blocklen(SHA2_384_CTX)), false)
"""
    SHA2_512_CTX()

Construct an empty SHA2_512 context.
"""
SHA2_512_CTX() = SHA2_512_CTX(copy(SHA2_512_initial_hash_value), 0, zeros(UInt8, blocklen(SHA2_512_CTX)), false)
"""
    SHA2_512_224_CTX()

Construct an empty SHA2_512/224 context and set the initial hash value.

For the source of the initial value,
refer to [FIPS 180-4, 5.3.6.1 SHA-512/224](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
"""
SHA2_512_224_CTX() = SHA2_512_224_CTX(copy(SHA2_512_224_initial_hash_value), 0, zeros(UInt8, blocklen(SHA2_512_224_CTX)), false)
"""
    SHA2_512_256_CTX()

Construct an empty SHA2_512/256 context and set the initial hash value.

For the source of the initial value,
refer to [FIPS 180-4, 5.3.6.2 SHA-512/256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
"""
SHA2_512_256_CTX() = SHA2_512_256_CTX(copy(SHA2_512_256_initial_hash_value), 0, zeros(UInt8, blocklen(SHA2_512_256_CTX)), false)

"""
    SHA3_224_CTX()

Construct an empty SHA3_224 context.
"""
SHA3_224_CTX() = SHA3_224_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHA3_224_CTX)), false)
"""
    SHA3_256_CTX()

Construct an empty SHA3_256 context.
"""
SHA3_256_CTX() = SHA3_256_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHA3_256_CTX)), false)
"""
    SHA3_384_CTX()

Construct an empty SHA3_384 context.
"""
SHA3_384_CTX() = SHA3_384_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHA3_384_CTX)), false)
"""
    SHA3_512_CTX()

Construct an empty SHA3_512 context.
"""
SHA3_512_CTX() = SHA3_512_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHA3_512_CTX)), false)

# SHA1 is special; he needs extra workspace
"""
    SHA1_CTX()

Construct an empty SHA1 context.
"""
SHA1_CTX() = SHA1_CTX(copy(SHA1_initial_hash_value), 0, zeros(UInt8, blocklen(SHA1_CTX)), Vector{UInt32}(undef, 80), false)


# Copy functions
copy(ctx::T) where {T<:SHA1_CTX} = T(copy(ctx.state), ctx.bytecount, copy(ctx.buffer), copy(ctx.W), ctx.used)
copy(ctx::T) where {T<:SHA2_CTX} = T(copy(ctx.state), ctx.bytecount, copy(ctx.buffer), ctx.used)
copy(ctx::T) where {T<:SHA3_CTX} = T(copy(ctx.state), ctx.bytecount, copy(ctx.buffer), ctx.used)


# Make printing these types a little friendlier
import Base.show
show(io::IO, ::SHA1_CTX) = print(io, "SHA1 hash state")
show(io::IO, ::SHA2_224_CTX) = print(io, "SHA2 224-bit hash state")
show(io::IO, ::SHA2_256_CTX) = print(io, "SHA2 256-bit hash state")
show(io::IO, ::SHA2_384_CTX) = print(io, "SHA2 384-bit hash state")
show(io::IO, ::SHA2_512_CTX) = print(io, "SHA2 512-bit hash state")
show(io::IO, ::SHA2_512_224_CTX) = print(io, "SHA2 512/224-bit hash state")
show(io::IO, ::SHA2_512_256_CTX) = print(io, "SHA2 512/256-bit hash state")
show(io::IO, ::SHA3_224_CTX) = print(io, "SHA3 224-bit hash state")
show(io::IO, ::SHA3_256_CTX) = print(io, "SHA3 256-bit hash state")
show(io::IO, ::SHA3_384_CTX) = print(io, "SHA3 384-bit hash state")
show(io::IO, ::SHA3_512_CTX) = print(io, "SHA3 512-bit hash state")


# use our types to define a method to get a pointer to the state buffer
buffer_pointer(ctx::T) where {T<:SHA_CTX} = Ptr{state_type(T)}(pointer(ctx.buffer))
