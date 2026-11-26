# Hardware-accelerated SHA-1 and SHA-224/SHA-256 using the ARMv8 Cryptographic
# Extension (SHA1C/P/M/H, SHA1SU0/SU1, SHA256H/H2, SHA256SU0/SU1 instructions).
# The architecture guarantees that the SHA-1 instructions are present whenever the
# SHA-256 instructions are (FEAT_SHA256 implies FEAT_SHA1), so one check covers both.
#
# Availability is detected at runtime (see `sha_hw_available`), so a package
# image compiled on one machine remains correct on another.

const V4U32 = NTuple{4,VecElement{UInt32}}
const V8U32 = NTuple{8,VecElement{UInt32}}

# The SHA instructions are emitted as inline assembly rather than LLVM intrinsics.
# Intrinsics require the `sha2` target feature on the function that uses them, and a
# function's own "target-features" attribute replaces (rather than extends) the
# features of the CPU Julia compiles for, and is in turn overridden by Julia when
# building multi-versioned (package or system) images. The assembler accepts the
# instructions regardless of the compilation target thanks to `.arch_extension`, so
# everything else is compiled for the actual target. The instructions are only ever
# executed when the runtime check `sha_hw_available()` passed.

# IR calling a SHA instruction as inline assembly. In `insn`, the output is operand $0,
# which is tied to the first input $1.
function sha_asm(ret, insn, constraints, args)
    return "call $ret asm \".arch_extension sha2\\0A$insn\", \"$constraints\"($args)"
end

# Inputs: abcd, efgh (state), w0..w3 (message block as big-endian words).
# Output: the updated state as <8 x i32> (abcd, efgh).
const SHA256_COMPRESS_IR = let io = IOBuffer()
    v = "<4 x i32>"
    println(io, "define <8 x i32> @entry($v %abcd0, $v %efgh0, $v %w0, $v %w1, $v %w2, $v %w3) {")
    for g in 0:15
        k = join(("i32 $(K256[4g + i])" for i in 1:4), ", ")
        println(io, "  %wk$g = add $v %w$g, <$k>")
        if g < 12
            # extend the message schedule by four words
            println(io, "  %s$g = ", sha_asm(v, raw"sha256su0 $0.4s, $2.4s", "=w,0,w",
                                            "$v %w$g, $v %w$(g+1)"))
            println(io, "  %w$(g+4) = ", sha_asm(v, raw"sha256su1 $0.4s, $2.4s, $3.4s", "=w,0,w,w",
                                                "$v %s$g, $v %w$(g+2), $v %w$(g+3)"))
        end
        println(io, "  %abcd$(g+1) = ", sha_asm(v, raw"sha256h ${0:q}, ${2:q}, $3.4s", "=w,0,w,w",
                                               "$v %abcd$g, $v %efgh$g, $v %wk$g"))
        println(io, "  %efgh$(g+1) = ", sha_asm(v, raw"sha256h2 ${0:q}, ${2:q}, $3.4s", "=w,0,w,w",
                                               "$v %efgh$g, $v %abcd$g, $v %wk$g"))
    end
    println(io, """
          %abcd = add $v %abcd16, %abcd0
          %efgh = add $v %efgh16, %efgh0
          %r = shufflevector $v %abcd, $v %efgh, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>
          ret <8 x i32> %r
        }""")
    String(take!(io))
end

@inline sha256_compress(abcd::V4U32, efgh::V4U32, w0::V4U32, w1::V4U32, w2::V4U32, w3::V4U32) =
    Base.llvmcall((SHA256_COMPRESS_IR, "entry"), V8U32,
                  Tuple{V4U32,V4U32,V4U32,V4U32,V4U32,V4U32}, abcd, efgh, w0, w1, w2, w3)

@inline vbswap(a::V4U32) = Base.llvmcall(("""
    declare <4 x i32> @llvm.bswap.v4i32(<4 x i32>)
    define <4 x i32> @entry(<4 x i32> %a) #0 {
      %r = call <4 x i32> @llvm.bswap.v4i32(<4 x i32> %a)
      ret <4 x i32> %r
    }
    attributes #0 = { alwaysinline }
    """, "entry"), V4U32, Tuple{V4U32}, a)

# Load 16 (possibly unaligned) bytes as four big-endian UInt32 words
@inline load_be_v4u32(p::Ptr{UInt8}, i) = vbswap(unsafe_load(Ptr{V4U32}(p + 16 * (i - 1))))

"""
    sha256_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks)

Run the SHA-256 compression function over `nblocks` consecutive 64-byte blocks
starting at `p`, updating the 8-word `state` in place. Must only be called when
`sha_hw_available()` is `true`.
"""
function sha256_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks::Integer)
    @inbounds begin
        abcd = (VecElement(state[1]), VecElement(state[2]), VecElement(state[3]), VecElement(state[4]))
        efgh = (VecElement(state[5]), VecElement(state[6]), VecElement(state[7]), VecElement(state[8]))
    end
    for _ in 1:nblocks
        r = sha256_compress(abcd, efgh, load_be_v4u32(p, 1), load_be_v4u32(p, 2),
                            load_be_v4u32(p, 3), load_be_v4u32(p, 4))
        abcd = (r[1], r[2], r[3], r[4])
        efgh = (r[5], r[6], r[7], r[8])
        p += 64
    end
    @inbounds for i in 1:4
        state[i] = abcd[i].value
        state[i + 4] = efgh[i].value
    end
    return state
end

# SHA-1: same scheme as SHA-256 above.
#
# Inputs: abcd, e (in lane 0), w0..w3 (message block as raw little-endian loads).
# Output: the updated state as <8 x i32> (abcd, e in lane 4).
const SHA1_COMPRESS_IR = let io = IOBuffer()
    v = "<4 x i32>"
    println(io, """
        declare $v @llvm.bswap.v4i32($v)
        define <8 x i32> @entry($v %abcd0, $v %evec, $v %raw0, $v %raw1, $v %raw2, $v %raw3) {
          %e0 = extractelement $v %evec, i32 0""")
    for i in 0:3
        println(io, "  %m$i = call $v @llvm.bswap.v4i32($v %raw$i)")
    end
    for g in 0:19
        k = K1[g ÷ 5 + 1]
        f = ("sha1c", "sha1p", "sha1m", "sha1p")[g ÷ 5 + 1]
        println(io, "  %wk$g = add $v %m$g, <i32 $k, i32 $k, i32 $k, i32 $k>")
        if g < 16
            # extend the message schedule by four words
            println(io, "  %s$g = ", sha_asm(v, raw"sha1su0 $0.4s, $2.4s, $3.4s", "=w,0,w,w",
                                            "$v %m$g, $v %m$(g+1), $v %m$(g+2)"))
            println(io, "  %m$(g+4) = ", sha_asm(v, raw"sha1su1 $0.4s, $2.4s", "=w,0,w",
                                                "$v %s$g, $v %m$(g+3)"))
        end
        # E for the next four rounds is A rotated left by 30
        println(io, "  %a$g = extractelement $v %abcd$g, i32 0")
        println(io, "  %e$(g+1) = ", sha_asm("i32", raw"sha1h ${0:s}, ${1:s}", "=w,w", "i32 %a$g"))
        println(io, "  %abcd$(g+1) = ", sha_asm(v, f * raw" ${0:q}, ${2:s}, $3.4s", "=w,0,w,w",
                                               "$v %abcd$g, i32 %e$g, $v %wk$g"))
    end
    println(io, """
          %abcd = add $v %abcd20, %abcd0
          %e = add i32 %e20, %e0
          %ev = insertelement $v zeroinitializer, i32 %e, i32 0
          %r = shufflevector $v %abcd, $v %ev, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>
          ret <8 x i32> %r
        }""")
    String(take!(io))
end

@inline sha1_compress(abcd::V4U32, evec::V4U32, w0::V4U32, w1::V4U32, w2::V4U32, w3::V4U32) =
    Base.llvmcall((SHA1_COMPRESS_IR, "entry"), V8U32,
                  Tuple{V4U32,V4U32,V4U32,V4U32,V4U32,V4U32}, abcd, evec, w0, w1, w2, w3)

@inline load_v4u32(p::Ptr{UInt8}, i) = unsafe_load(Ptr{V4U32}(p + 16 * (i - 1)))

"""
    sha1_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks)

Run the SHA-1 compression function over `nblocks` consecutive 64-byte blocks
starting at `p`, updating the 5-word `state` in place. Must only be called when
`sha_hw_available()` is `true`.
"""
function sha1_blocks_hw!(state::Vector{UInt32}, p::Ptr{UInt8}, nblocks::Integer)
    @inbounds begin
        abcd = (VecElement(state[1]), VecElement(state[2]), VecElement(state[3]), VecElement(state[4]))
        evec = (VecElement(state[5]), VecElement(0x00000000), VecElement(0x00000000), VecElement(0x00000000))
    end
    for _ in 1:nblocks
        r = sha1_compress(abcd, evec, load_v4u32(p, 1), load_v4u32(p, 2),
                          load_v4u32(p, 3), load_v4u32(p, 4))
        abcd = (r[1], r[2], r[3], r[4])
        evec = (r[5], r[6], r[7], r[8])
        p += 64
    end
    @inbounds begin
        for i in 1:4
            state[i] = abcd[i].value
        end
        state[5] = evec[1].value
    end
    return state
end

function detect_sha_hw()
    CPUID = Base.BinaryPlatforms.CPUID
    return CPUID.test_cpu_feature(CPUID.JL_AArch64_sha2)
end
