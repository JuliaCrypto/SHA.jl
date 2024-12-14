abstract type SHAKE <: SHA3_CTX end 
# note, that field property used has differend uses, depending on T<:SHAKE or T<:SHA3_CTX
mutable struct SHAKE_128_CTX <: SHAKE
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    bc::Vector{UInt64}
    used::Bool
end
mutable struct SHAKE_256_CTX <: SHAKE
    state::Vector{UInt64}
    bytecount::UInt128
    buffer::Vector{UInt8}
    bc::Vector{UInt64}
    used::Bool
end

digestlen(::Type{SHAKE_128_CTX}) = 16
digestlen(::Type{SHAKE_256_CTX}) = 32
blocklen(::Type{SHAKE_128_CTX}) = UInt64(25*8 - 2*digestlen(SHAKE_128_CTX))
blocklen(::Type{SHAKE_256_CTX}) = UInt64(25*8 - 2*digestlen(SHAKE_256_CTX))
buffer_pointer(ctx::T) where {T<:SHAKE} = Ptr{state_type(T)}(pointer(ctx.buffer))

# construct an empty SHA context
SHAKE_128_CTX() = SHAKE_128_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHAKE_128_CTX)), Vector{UInt64}(undef, 5), false)
SHAKE_256_CTX() = SHAKE_256_CTX(zeros(UInt64, 25), 0, zeros(UInt8, blocklen(SHAKE_256_CTX)), Vector{UInt64}(undef, 5), false)

function transform!(context::T) where {T<:SHAKE}
    # First, update state with buffer
    pbuf = Ptr{eltype(context.state)}(pointer(context.buffer))
    # after SHAKE_256_MAX_READ (digestlen) is reached, simply work with context.state[idx]
    if !context.used 
        for idx in 1:div(blocklen(T),8)
            context.state[idx] = context.state[idx] ⊻ unsafe_load(pbuf, idx)
        end
    end 
    bc = context.bc
    state = context.state
    # We always assume 24 rounds
    @inbounds for round in 0:23
        # Theta function
        for i in 1:5
            bc[i] = state[i] ⊻ state[i + 5] ⊻ state[i + 10] ⊻ state[i + 15] ⊻ state[i + 20]
        end
        for i in 0:4
            temp = bc[rem(i + 4, 5) + 1] ⊻ L64(1, bc[rem(i + 1, 5) + 1])
            for j in 0:5:20
                state[Int(i + j + 1)] = state[i + j + 1] ⊻ temp
            end
        end
        # Rho Pi
        temp = state[2]
        for i in 1:24
            j = SHA3_PILN[i]
            bc[1] = state[j]
            state[j] = L64(SHA3_ROTC[i], temp)
            temp = bc[1]
        end
        # Chi
        for j in 0:5:20
            for i in 1:5
                bc[i] = state[i + j]
            end
            for i in 0:4
                state[j + i + 1] = state[j + i + 1] ⊻ (~bc[rem(i + 1, 5) + 1] & bc[rem(i + 2, 5) + 1])
            end
        end
        # Iota
        state[1] = state[1] ⊻ SHA3_ROUND_CONSTS[round+1]
    end
    return context.state
end
function digest!(context::T,d::UInt,p::Ptr{UInt8}) where {T<:SHAKE}
    usedspace = context.bytecount % blocklen(T)
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
    # Return the digest:
    # fill the given memory via pointer, if d>blocklen, update pointer and digest again.
    if d <= blocklen(T)
        for i = 1:d
            unsafe_store!(p,reinterpret(UInt8, context.state)[i],i)
        end 
        return
    else 
        for i = 1:blocklen(T)
            unsafe_store!(p,reinterpret(UInt8, context.state)[i],i)
        end 
        context.used = true
        p+=blocklen(T)
        next_d_len = UInt(d - blocklen(T))
        digest!(context, next_d_len, p)
        return 
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