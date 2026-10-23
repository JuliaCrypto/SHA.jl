# Nonlinear functions, in the forms that need the fewest operations
Round0(b, c, d) = UInt32(d ⊻ (b & (c ⊻ d)))
Round1And3(b, c, d) = UInt32(b ⊻ c ⊻ d)
Round2(b, c, d) = UInt32((b & c) | (d & (b | c)))

# Five rounds. Instead of shifting the working variables after every round,
# their roles rotate, so that after five rounds they are back in place.
@inline function rounds5(f, a, b, c, d, e, W, i, k)
    @inbounds begin
        e += lrot(5, a, 32) + f(b, c, d) + W[i] + k;     b = lrot(30, b, 32)
        d += lrot(5, e, 32) + f(a, b, c) + W[i + 1] + k; a = lrot(30, a, 32)
        c += lrot(5, d, 32) + f(e, a, b) + W[i + 2] + k; e = lrot(30, e, 32)
        b += lrot(5, c, 32) + f(d, e, a) + W[i + 3] + k; d = lrot(30, d, 32)
        a += lrot(5, b, 32) + f(c, d, e) + W[i + 4] + k; c = lrot(30, c, 32)
    end
    return a, b, c, d, e
end

function transform!(context::SHA1_CTX)
    # Buffer is 16 elements long, we expand to 80
    W = context.W
    pbuf = buffer_pointer(context)
    @inbounds for i in 1:16
        W[i] = bswap(unsafe_load(pbuf, i))
    end

    # First round of expansions
    @inbounds for i in 17:32
        W[i] = lrot(1, W[i-3] ⊻ W[i-8] ⊻ W[i-14] ⊻ W[i-16], 32)
    end

    # Second round of expansions (possibly 4-way SIMD-able)
    @inbounds for i in 33:80
        W[i] = lrot(2, W[i-6] ⊻ W[i-16] ⊻ W[i-28] ⊻ W[i-32], 32)
    end

    # Initialize registers with the previous intermediate values (our state)
    state = context.state
    a, b, c, d, e = state[1], state[2], state[3], state[4], state[5]

    # Run our rounds, manually separated into the four rounds; using an array of lambdas
    # really kills performance and causes a huge number of allocations
    for i in 1:5:20
        a, b, c, d, e = rounds5(Round0, a, b, c, d, e, W, i, K1[1])
    end
    for i in 21:5:40
        a, b, c, d, e = rounds5(Round1And3, a, b, c, d, e, W, i, K1[2])
    end
    for i in 41:5:60
        a, b, c, d, e = rounds5(Round2, a, b, c, d, e, W, i, K1[3])
    end
    for i in 61:5:80
        a, b, c, d, e = rounds5(Round1And3, a, b, c, d, e, W, i, K1[4])
    end

    state[1] += a
    state[2] += b
    state[3] += c
    state[4] += d
    state[5] += e
end
