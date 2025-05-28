@inline function keccak_theta(state::NTuple{25,UInt64})
    C = ntuple(i -> state[i] ⊻ state[i + 5] ⊻ state[i + 10] ⊻ state[i + 15] ⊻ state[i + 20], Val(5))
    D = ntuple(i -> C[rem(i + 3, 5) + 1] ⊻ L64(1, C[rem(i, 5) + 1]), Val(5))
    return ntuple(k -> state[k] ⊻ D[rem(k - 1, 5) + 1], Val(25))
end

@inline keccak_rho(state::NTuple{25,UInt64}) =
    ntuple(k -> bitrotate(state[k], SHA3_ROTC[k]), Val(25))

@inline keccak_pi(state::NTuple{25,UInt64}) =
    ntuple(k -> state[SHA3_PILN[k]], Val(25))

@inline function keccak_chi(state::NTuple{25,UInt64})
    return ntuple(
        k -> let j = k - rem(k - 1, 5)
            state[k] ⊻ (~state[rem(k, 5) + j] & state[rem(k + 1, 5) + j])
        end,
        Val(25)
    )
end

@inline keccak_iota(round, state::NTuple{25,UInt64}) =
    (state[1] ⊻ SHA3_ROUND_CONSTS[round+1], state[2:end]...)

function transform!(context::T) where {T<:SHA3_CTX}
    # First, update state with buffer
    pbuf = Ptr{eltype(context.state)}(pointer(context.buffer))
    for idx in 1:div(blocklen(T),8)
        context.state[idx] = context.state[idx] ⊻ unsafe_load(pbuf, idx)
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



# Finalize data in the buffer, append total bitlength, and return our precious hash!
function digest!(context::T) where {T<:SHA3_CTX}
    if !context.used
        usedspace = context.bytecount % blocklen(T)
        # If we have anything in the buffer still, pad and transform that data
        if usedspace < blocklen(T) - 1
            # Begin padding with a 0x06
            context.buffer[usedspace+1] = 0x06
            # Fill with zeros up until the last byte
            context.buffer[usedspace+2:end-1] .= 0x00
            # Finish it off with a 0x80
            context.buffer[end] = 0x80
        else
            # Otherwise, we have just a single byte of padding to add
            # X-ref: https://crypto.stackexchange.com/a/40515
            context.buffer[end] = 0x86
        end

        # Final transform:
        transform!(context)
        context.used = true
    end

    # Return the digest
    return reinterpret(UInt8, context.state)[1:digestlen(T)]
end
