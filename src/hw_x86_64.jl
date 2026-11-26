# Hardware-accelerated SHA-1 and SHA-224/SHA-256 using the x86 SHA extensions
# (SHA-NI: SHA1RNDS4, SHA1NEXTE, SHA1MSG1/2, SHA256RNDS2, SHA256MSG1/2 instructions).
#
# Availability is detected at runtime (see `sha_hw_available`), so a package
# image compiled on one machine remains correct on another.

const V4U32 = NTuple{4,VecElement{UInt32}}
const V8U32 = NTuple{8,VecElement{UInt32}}

# The SHA instructions are emitted as inline assembly rather than LLVM intrinsics.
# Intrinsics require the `sha` target feature on the function that uses them, and a
# function's own "target-features" attribute replaces (rather than extends) the
# features of the CPU Julia compiles for, and is in turn overridden by Julia when
# building multi-versioned (package or system) images. The assembler accepts the
# instructions regardless of the compilation target, so everything else is compiled
# for the actual target. The instructions are only ever executed when the runtime
# check `sha_hw_available()` passed.
#
# SHA256RNDS2 operates on the state split as ABEF = (F, E, B, A) and
# CDGH = (H, G, D, C) (lane 0 first), and performs two rounds per instruction
# using the two low words of its third operand.

# IR calling a SHA instruction as inline assembly (AT&T syntax). In `insn`, the output
# is operand $0, which is tied to the first input $1. The `x` constraint restricts
# operands to xmm0-xmm15, which the legacy-encoded SHA instructions can address.
function sha_asm(insn, args; xmm0=false)
    v = "<4 x i32>"
    constraints = xmm0 ? "=x,0,x,{xmm0}" : "=x,0,x"
    return "call $v asm \"$insn\", \"$constraints\"($(join(("$v %$a" for a in args), ", ")))"
end

# Inputs: abef, cdgh (state), w0..w3 (message block as raw little-endian loads).
# Output: the updated state as <8 x i32> (abef, cdgh).
const SHA256_COMPRESS_IR = let io = IOBuffer()
    v = "<4 x i32>"
    println(io, """
        declare $v @llvm.bswap.v4i32($v)
        define <8 x i32> @entry($v %abef0, $v %cdgh0, $v %raw0, $v %raw1, $v %raw2, $v %raw3) {""")
    for i in 0:3
        println(io, "  %m$i = call $v @llvm.bswap.v4i32($v %raw$i)")
    end
    for g in 0:15
        k = join(("i32 $(K256[4g + i])" for i in 1:4), ", ")
        println(io, "  %wk$g = add $v %m$g, <$k>")
        if g < 12
            # extend the message schedule by four words:
            # m[g+4] = msg2(msg1(m[g], m[g+1]) + (m[g+2][1:3], m[g+3][0]), m[g+3])
            println(io, "  %s1_$g = ", sha_asm(raw"sha256msg1 $2, $0", ("m$g", "m$(g+1)")))
            println(io, "  %al$g = shufflevector $v %m$(g+2), $v %m$(g+3), <4 x i32> <i32 1, i32 2, i32 3, i32 4>")
            println(io, "  %s2_$g = add $v %s1_$g, %al$g")
            println(io, "  %m$(g+4) = ", sha_asm(raw"sha256msg2 $2, $0", ("s2_$g", "m$(g+3)")))
        end
        # Rounds 4g, 4g+1 produce the new ABEF, which with the old ABEF (now in
        # the CDGH position) feed rounds 4g+2, 4g+3 using the upper two words of wk.
        println(io, "  %cdgh$(g+1) = ", sha_asm(raw"sha256rnds2 $2, $0", ("cdgh$g", "abef$g", "wk$g"); xmm0=true))
        println(io, "  %wkhi$g = shufflevector $v %wk$g, $v %wk$g, <4 x i32> <i32 2, i32 3, i32 0, i32 0>")
        println(io, "  %abef$(g+1) = ", sha_asm(raw"sha256rnds2 $2, $0", ("abef$g", "cdgh$(g+1)", "wkhi$g"); xmm0=true))
    end
    println(io, """
          %abef = add $v %abef16, %abef0
          %cdgh = add $v %cdgh16, %cdgh0
          %r = shufflevector $v %abef, $v %cdgh, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>
          ret <8 x i32> %r
        }""")
    String(take!(io))
end

@inline sha256_compress(abef::V4U32, cdgh::V4U32, w0::V4U32, w1::V4U32, w2::V4U32, w3::V4U32) =
    Base.llvmcall((SHA256_COMPRESS_IR, "entry"), V8U32,
                  Tuple{V4U32,V4U32,V4U32,V4U32,V4U32,V4U32}, abef, cdgh, w0, w1, w2, w3)

# Load 16 (possibly unaligned) bytes
@inline load_v4u32(p::Ptr{UInt8}, i) = unsafe_load(Ptr{V4U32}(p + 16 * (i - 1)))

"""
    sha256_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks)

Run the SHA-256 compression function over `nblocks` consecutive 64-byte blocks
starting at `p`, updating the 8-word `state` in place. Must only be called when
`sha_hw_available()` is `true`.
"""
function sha256_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks::Integer)
    @inbounds begin
        abef = (VecElement(state[6]), VecElement(state[5]), VecElement(state[2]), VecElement(state[1]))
        cdgh = (VecElement(state[8]), VecElement(state[7]), VecElement(state[4]), VecElement(state[3]))
    end
    for _ in 1:nblocks
        r = sha256_compress(abef, cdgh, load_v4u32(p, 1), load_v4u32(p, 2),
                            load_v4u32(p, 3), load_v4u32(p, 4))
        abef = (r[1], r[2], r[3], r[4])
        cdgh = (r[5], r[6], r[7], r[8])
        p += 64
    end
    @inbounds begin
        state[1] = abef[4].value; state[2] = abef[3].value
        state[3] = cdgh[4].value; state[4] = cdgh[3].value
        state[5] = abef[2].value; state[6] = abef[1].value
        state[7] = cdgh[2].value; state[8] = cdgh[1].value
    end
    return state
end

# SHA-1: same scheme as SHA-256 above. The SHA-1 instructions keep the first word
# in the *high* lane: ABCD = (D, C, B, A), message words (W3, W2, W1, W0), and E
# in lane 3. SHA1RNDS4 performs four rounds with E pre-added to W0; SHA1NEXTE
# derives that E from the A of four rounds earlier (rotated left by 30).
#
# Inputs: abcd, e (in lane 3), w0..w3 (message block as raw little-endian loads).
# Output: the updated state as <8 x i32> (abcd, e in lane 7).
const SHA1_COMPRESS_IR = let io = IOBuffer()
    v = "<4 x i32>"
    println(io, """
        declare $v @llvm.bswap.v4i32($v)
        define <8 x i32> @entry($v %abcd0, $v %e0, $v %raw0, $v %raw1, $v %raw2, $v %raw3) {""")
    for i in 0:3
        # byteswap each word and reverse the word order
        println(io, "  %bs$i = call $v @llvm.bswap.v4i32($v %raw$i)")
        println(io, "  %m$i = shufflevector $v %bs$i, $v %bs$i, <4 x i32> <i32 3, i32 2, i32 1, i32 0>")
    end
    for g in 0:19
        if g < 16
            # extend the message schedule by four words:
            # m[g+4] = msg2(msg1(m[g], m[g+1]) ^ m[g+2], m[g+3])
            println(io, "  %s1_$g = ", sha_asm(raw"sha1msg1 $2, $0", ("m$g", "m$(g+1)")))
            println(io, "  %x$g = xor $v %s1_$g, %m$(g+2)")
            println(io, "  %m$(g+4) = ", sha_asm(raw"sha1msg2 $2, $0", ("x$g", "m$(g+3)")))
        end
        if g == 0
            println(io, "  %we0 = add $v %e0, %m0")
        else
            println(io, "  %we$g = ", sha_asm(raw"sha1nexte $2, $0", ("abcd$(g-1)", "m$g")))
        end
        # the immediate selects the round function and constant: $$ is a literal $
        println(io, "  %abcd$(g+1) = ", sha_asm("sha1rnds4 \$\$$(g ÷ 5), \$2, \$0", ("abcd$g", "we$g")))
    end
    println(io, "  %e = ", sha_asm(raw"sha1nexte $2, $0", ("abcd19", "e0")))
    println(io, """
          %abcd = add $v %abcd20, %abcd0
          %r = shufflevector $v %abcd, $v %e, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>
          ret <8 x i32> %r
        }""")
    String(take!(io))
end

@inline sha1_compress(abcd::V4U32, evec::V4U32, w0::V4U32, w1::V4U32, w2::V4U32, w3::V4U32) =
    Base.llvmcall((SHA1_COMPRESS_IR, "entry"), V8U32,
                  Tuple{V4U32,V4U32,V4U32,V4U32,V4U32,V4U32}, abcd, evec, w0, w1, w2, w3)

"""
    sha1_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks)

Run the SHA-1 compression function over `nblocks` consecutive 64-byte blocks
starting at `p`, updating the 5-word `state` in place. Must only be called when
`sha_hw_available()` is `true`.
"""
function sha1_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks::Integer)
    z = VecElement(0x00000000)
    @inbounds begin
        abcd = (VecElement(state[4]), VecElement(state[3]), VecElement(state[2]), VecElement(state[1]))
        evec = (z, z, z, VecElement(state[5]))
    end
    for _ in 1:nblocks
        r = sha1_compress(abcd, evec, load_v4u32(p, 1), load_v4u32(p, 2),
                          load_v4u32(p, 3), load_v4u32(p, 4))
        abcd = (r[1], r[2], r[3], r[4])
        evec = (z, z, z, r[8])
        p += 64
    end
    @inbounds begin
        state[1] = abcd[4].value; state[2] = abcd[3].value
        state[3] = abcd[2].value; state[4] = abcd[1].value
        state[5] = evec[4].value
    end
    return state
end

function detect_sha_hw()
    CPUID = Base.BinaryPlatforms.CPUID
    # `JL_X86_sse41` was renamed to `JL_X86_sse4_1` in Julia 1.14
    sse41 = isdefined(CPUID, :JL_X86_sse4_1) ? CPUID.JL_X86_sse4_1 : CPUID.JL_X86_sse41
    return CPUID.test_cpu_feature(CPUID.JL_X86_sha) &&
           CPUID.test_cpu_feature(CPUID.JL_X86_ssse3) &&
           CPUID.test_cpu_feature(sse41)
end
