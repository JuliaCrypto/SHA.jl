# NIST CAVS —— Cryptographic Algorithm Validation Program
#   Main page:  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
#   Secure-Hashing: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing
#       SHA1: SHA-1
#       SHA2: SHA-224 SHA-256 SHA-384 SHA-512 SHA-512/224 SHA-512/256
#       SHA3: SHA3-224 SHA3-256 SHA3-384 SHA3-512
#       XOFs: SHAKE128 SHAKE256
#   Copyrights: https://www.nist.gov/oism/copyrights
include("cavs_const.jl")


"""Generate 100 Monte Carlo test checkpoints for SHA1 and SHA2.

## Code for Generating Pseudorandom Messages

    INPUT: Seed - A random seed n bits long
    {
        for (j=0; j<100; j++) {
            MD0 = MD1 = MD2 = Seed;
            for (i=3; i<1003; i++) {
                Mi = MDi-3 || MDi-2 || MDi-1;
                MDi = SHA(Mi);
            }
            MDj = Seed = MD1002;
            OUTPUT: MDj
        }
    }

Note: `||` stand for array concatenate.

xref: Section 6.4
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf
"""
function sha12_monte_carlo_checkpoints(seed_in, seed_len::Int, sha_f::Function)
    seed = hex2bytes(seed_in)
    @assert size(seed) == (seed_len,)

    md = Matrix{UInt8}(undef, 100, seed_len)
    for j in Base.OneTo(100)
        x = y = z = seed
        for _ in 1:1000
            m_i = vcat(x, y, z)  # 60-element Vector{UInt8}
            md_i = sha_f(m_i)
            x, y, z = y, z, md_i
        end
        md_j = seed = z
        md[j,:] = md_j
    end
    md
end

function sha12_csvs_msg(sha_f::Function)
    p = CAVS_TESTSET_12[sha_f]
    md = sha12_monte_carlo_checkpoints(p.seed, p.seed_len, sha_f)
    [ bytes2hex(row) for row in eachrow(md) ]
end


"""Generate 100 Monte Carlo test checkpoints for SHA3.


## Code for Generating Pseudorandom Messages

    INPUT: A random Seed n bits long
    {
        MD0 = Seed;
        for (j=0; j<100; j++) {
            for (i=1; i<1001; i++) {
                Msgi = MDi-1;
                MDi = SHA3(Msgi);
            }
            MD0 = MD1000;
            OUTPUT: MD0
        }
    }

xref: Section 6.2.3
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
"""
function sha3_monte_carlo_checkpoints(seed_in, seed_len::Int, sha_f::Function)
    seed = hex2bytes(seed_in)
    @assert size(seed) == (seed_len,)

    md = Matrix{UInt8}(undef, 100, seed_len)
    for j in Base.OneTo(100)
        for _ in 1:1000
            seed = sha_f(seed)
        end
        md[j,:] = seed
    end
    md
end

function sha3_csvs_msg(sha_f::Function)
    p = CAVS_TESTSET_3[sha_f]
    md = sha3_monte_carlo_checkpoints(p.seed, p.seed_len, sha_f)
    [ bytes2hex(row) for row in eachrow(md) ]
end
