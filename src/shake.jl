abstract type SHAKE <: SHA3_CTX end 
# note, that field property used has differend uses, depending on T<:SHAKE or T<:SHA3_CTX
mutable struct SHAKE_128_CTX <: SHAKE
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end
mutable struct SHAKE_256_CTX <: SHAKE
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    used::Bool
end

digestlen(::Type{SHAKE_128_CTX}) = 16
digestlen(::Type{SHAKE_256_CTX}) = 32
blocklen(::Type{SHAKE_128_CTX}) = UInt64(25*8 - 2*digestlen(SHAKE_128_CTX))
blocklen(::Type{SHAKE_256_CTX}) = UInt64(25*8 - 2*digestlen(SHAKE_256_CTX))
buffer_pointer(ctx::T) where {T<:SHAKE} = Ptr{state_type(T)}(pointer(ctx.buffer))

# construct an empty SHA context
SHAKE_128_CTX() = SHAKE_128_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHAKE_128_CTX)), false)
SHAKE_256_CTX() = SHAKE_256_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHAKE_256_CTX)), false)

function transform!(context::T) where {T<:SHAKE}
    # First, update state with buffer
    pbuf = Ptr{eltype(context.state)}(pointer(context.buffer))
    # after SHAKE_256_MAX_READ (digestlen) is reached, simply work with context.state[idx]
    if !context.used 
        for idx in 1:div(blocklen(T),8)
            context.state[idx] = context.state[idx] ⊻ unsafe_load(pbuf, idx)
        end
    end 

    state = let s = context.state; ntuple(i -> s[i], Val(25)); end

    # We always assume 24 rounds
    for round in 0:23
        state = keccak_theta(state)
        state = keccak_rho(state)
        state = keccak_pi(state)
        state = keccak_chi(state)
        state = keccak_iota(round, state)
    end

    for k in 1:25
        context.state[k] = state[k]
    end

    return context.state
end
function digest!(context::T,d::UInt,p::Ptr{UInt8}) where {T<:SHAKE}
    usedspace = context.bytecount % blocklen(T)
    if !context.used
        # If we have anything in the buffer still, pad and transform that data
        if usedspace < blocklen(T) - 1
            # Begin padding with a 0x1f
            context.buffer[usedspace+1] = 0x1f
            # Fill with zeros up until the last byte
            context.buffer[usedspace+2:end-1] .= 0x00
            # Finish it off with a 0x80
            context.buffer[end] = 0x80
        else
            # Otherwise, we have to add on a whole new buffer
            context.buffer[end] = 0x9f
        end
        # Final transform:
        transform!(context)

        context.used = true
        context.bytecount = 0
        usedspace = 0
    end
    # Return the digest:
    # fill the given memory via pointer, if d>blocklen, update pointer and digest again.
    while d > 0
        avail = blocklen(T) - usedspace
        len = min(d, avail)
        for i = 1:len
            unsafe_store!(p,reinterpret(UInt8, context.state)[usedspace+i],i)
        end
        context.bytecount += len
        p += len
        d = UInt(d - len)
        if len == avail
            transform!(context)
            usedspace = context.bytecount % blocklen(T)
        end
    end
end

"""
    shake128(data::AbstractBytes,d::UInt)

Hash data using the `shake128` algorithm and return the first d resulting bytes.
"""
function shake128(data::AbstractBytes,d::UInt)
    ctx = SHAKE_128_CTX()
    update!(ctx, data)
    M = Vector{UInt8}(undef,d)     # prealloc
    p = pointer(M)
    digest!(ctx,d,p)
    return M
end
"""
    shake256(data::AbstractBytes,d::UInt)

Hash data using the `shake258` algorithm and return the first d resulting bytes.
"""
function shake256(data::AbstractBytes,d::UInt)
    ctx = SHAKE_256_CTX()
    update!(ctx, data)
    M = Vector{UInt8}(undef,d)     # prealloc
    p = pointer(M)
    digest!(ctx,d,p)
    return M
end