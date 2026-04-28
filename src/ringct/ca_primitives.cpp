// Copyright (c) 2024 Beldex Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Confidential Assets (CA) cryptographic primitives – implementation.
// See ca_primitives.h for the full API documentation.

#include "ca_primitives.h"

#include <cstring>
#include <stdexcept>

#include "epee/misc_log_ex.h"
#include "crypto/crypto.h"

extern "C" {
#include "crypto/crypto-ops.h"
}

// CHECK_AND_ASSERT_THROW_MES is provided by epee (misc_log_ex.h)

namespace ca {

// ============================================================================
// Internal helpers
// ============================================================================

namespace {

// Hash an arbitrary byte string to a curve point in the prime-order subgroup.
//
// The pipeline (following the Monero/Beldex convention in rctOps.cpp):
//   1. cn_fast_hash(data, len)              → 32-byte digest  h
//   2. rct::hash_to_p3(p3, h)              → cn_fast_hash(h) → Elligator → ×8
//
// The extra cn_fast_hash inside hash_to_p3 means the curve point is derived
// from a double hash of the input, which is fine and fully deterministic.
static rct::key bytes_to_generator(const void* data, std::size_t len)
{
    // Step 1: hash the raw input to a 32-byte key (no scalar reduction needed
    // here; we only need a uniform 32-byte domain value for hash_to_p3)
    crypto::hash h;
    crypto::cn_fast_hash(data, len, h);

    rct::key hk;
    std::memcpy(hk.bytes, h.data, 32);

    // Step 2: map to a prime-order curve point via Elligator + ×8
    // hash_to_p3 applies cn_fast_hash(hk) internally before Elligator,
    // so the final point is derived from a double-hash of the input.
    ge_p3 p3;
    rct::hash_to_p3(p3, hk);

    rct::key result;
    ge_p3_tobytes(result.bytes, &p3);
    return result;
}

// Build a Fiat-Shamir challenge scalar by concatenating 32-byte inputs.
//
//   c = cn_fast_hash(k0 || k1 || ... || kn)  reduced mod l
//
// Using a flat concatenation (all elements are fixed 32 bytes) is safe and
// matches the pattern used in CLSAG and Bulletproofs+ within this codebase.
static rct::key fiat_shamir(std::initializer_list<const rct::key*> keys)
{
    const std::size_t n = keys.size();
    std::vector<unsigned char> buf;
    buf.reserve(n * 32);
    for (const rct::key* k : keys)
        buf.insert(buf.end(), k->bytes, k->bytes + 32);

    rct::key result;
    rct::hash_to_scalar(result, buf.data(), buf.size());
    return result;
}

// Variable-length overload used by the aggregation proof where the number of
// inputs is not known at compile time.
static rct::key fiat_shamir_vec(const std::vector<const rct::key*>& keys)
{
    std::vector<unsigned char> buf;
    buf.reserve(keys.size() * 32);
    for (const rct::key* k : keys)
        buf.insert(buf.end(), k->bytes, k->bytes + 32);

    rct::key result;
    rct::hash_to_scalar(result, buf.data(), buf.size());
    return result;
}

// Compute  a*P + b*Q  (two arbitrary point multiplications then add)
static rct::key two_point_mult(
    const rct::key& a, const rct::key& P,
    const rct::key& b, const rct::key& Q)
{
    const rct::key aP = rct::scalarmultKey(P, a);
    const rct::key bQ = rct::scalarmultKey(Q, b);
    return rct::addKeys(aP, bQ);
}

// Compute  a*P + b*G  (one arbitrary multiplication + one base multiplication)
static rct::key point_mult_plus_base(
    const rct::key& a, const rct::key& P,
    const rct::key& b)
{
    const rct::key aP = rct::scalarmultKey(P, a);
    const rct::key bG = rct::scalarmultBase(b);
    return rct::addKeys(aP, bG);
}

} // anonymous namespace

// ============================================================================
// 1.  NUMS generator points
// ============================================================================

const rct::key& get_X()
{
    // Computed once at first call; the domain string is the authoritative
    // derivation path – changing it would break all existing proofs.
    static const rct::key X = []() {
        const char domain[] = "Beldex CA X v1";
        return bytes_to_generator(domain, sizeof(domain) - 1);
    }();
    return X;
}

const rct::key& get_U()
{
    static const rct::key U = []() {
        const char domain[] = "Beldex CA U v1";
        return bytes_to_generator(domain, sizeof(domain) - 1);
    }();
    return U;
}

// ============================================================================
// 2.  Per-asset generator
// ============================================================================

rct::key compute_asset_generator(const crypto::hash& asset_descriptor_hash)
{
    // Use the raw descriptor hash bytes as the domain input.  hash_to_p3
    // will apply cn_fast_hash again internally, giving two rounds before
    // the hash-to-curve step – consistent with the attack-resistance note
    // in the Zano whitepaper Section 3.
    rct::key domain;
    std::memcpy(domain.bytes, asset_descriptor_hash.data, 32);

    ge_p3 p3;
    rct::hash_to_p3(p3, domain);

    rct::key Ht;
    ge_p3_tobytes(Ht.bytes, &p3);
    return Ht;
}

// ============================================================================
// 3.  Blinded asset tag
// ============================================================================

rct::key blind_asset_tag(const rct::key& Ht, const rct::key& r)
{
    // T = Ht + r*X
    const rct::key rX = rct::scalarmultKey(get_X(), r);
    return rct::addKeys(Ht, rX);
}

rct::key unblind_asset_tag(const rct::key& T, const rct::key& r)
{
    // Ht = T - r*X
    const rct::key rX = rct::scalarmultKey(get_X(), r);
    rct::key Ht;
    rct::subKeys(Ht, T, rX);
    return Ht;
}

// ============================================================================
// 4.  Schnorr proof over X
// ============================================================================

schnorr_sig_X generate_schnorr_X(
    const rct::key& m,
    const rct::key& A,
    const rct::key& x)
{
    schnorr_sig_X sig;

    // Pick random nonce  k ← Zl
    const rct::key k = rct::skGen();

    // Commitment  R = k * X
    const rct::key R = rct::scalarmultKey(get_X(), k);

    // Fiat-Shamir challenge  c = Hs(m || A || R)
    sig.c = fiat_shamir({&m, &A, &R});

    // Response  y = k - c*x  mod l
    // sc_mulsub(r, a, b, c)  computes  r = c - a*b  mod l
    sc_mulsub(sig.y.bytes, sig.c.bytes, x.bytes, k.bytes);

    return sig;
}

bool verify_schnorr_X(
    const rct::key& m,
    const rct::key& A,
    const schnorr_sig_X& sig) noexcept
{
    try {
        // Reject non-canonical scalars immediately
        if (sc_check(sig.c.bytes) != 0 || sc_check(sig.y.bytes) != 0)
            return false;

        // Recompute commitment  R' = y*X + c*A
        const rct::key Rprime = two_point_mult(sig.y, get_X(), sig.c, A);

        // Recompute and compare challenge
        const rct::key c_check = fiat_shamir({&m, &A, &Rprime});
        return (sig.c == c_check);
    }
    catch (...) {
        return false;
    }
}

// ============================================================================
// 5.  Double Schnorr / balance proof
// ============================================================================

double_schnorr_sig generate_balance_proof(
    const rct::key& m,
    const rct::key& Balance,
    const rct::key& r,
    const rct::key& y)
{
    double_schnorr_sig sig;

    // Random nonces
    const rct::key k0 = rct::skGen();
    const rct::key k1 = rct::skGen();

    // Commitment  R = k0*X + k1*G
    const rct::key R = point_mult_plus_base(k0, get_X(), k1);

    // Fiat-Shamir  c = Hs(m || Balance || R)
    sig.c = fiat_shamir({&m, &Balance, &R});

    // Responses:
    //   y0 = k0 - c*r  mod l   (X component)
    //   y1 = k1 - c*y  mod l   (G component)
    sc_mulsub(sig.y0.bytes, sig.c.bytes, r.bytes, k0.bytes);
    sc_mulsub(sig.y1.bytes, sig.c.bytes, y.bytes, k1.bytes);

    return sig;
}

bool verify_balance_proof(
    const rct::key& m,
    const rct::key& Balance,
    const double_schnorr_sig& sig) noexcept
{
    try {
        if (sc_check(sig.c.bytes)  != 0 ||
            sc_check(sig.y0.bytes) != 0 ||
            sc_check(sig.y1.bytes) != 0)
            return false;

        // R' = y0*X + y1*G + c*Balance
        //
        // Correctness:
        //   y0*X + y1*G + c*Balance
        //   = (k0-c*r)*X + (k1-c*y)*G + c*(r*X + y*G)
        //   = k0*X + k1*G
        //   = R   ✓
        const rct::key y0X    = rct::scalarmultKey(get_X(), sig.y0);
        const rct::key y1G    = rct::scalarmultBase(sig.y1);
        const rct::key cBal   = rct::scalarmultKey(Balance, sig.c);

        rct::key Rprime;
        rct::addKeys(Rprime, y0X, y1G);
        rct::addKeys(Rprime, Rprime, cBal);

        const rct::key c_check = fiat_shamir({&m, &Balance, &Rprime});
        return (sig.c == c_check);
    }
    catch (...) {
        return false;
    }
}

// ============================================================================
// 6.  Vector UG aggregation proof
// ============================================================================

UG_aggregation_proof generate_UG_aggregation_proof(
    const rct::key&              m,
    const rct::keyV&             amounts,
    const rct::keyV&             out_blinds,
    const rct::keyV&             agg_blinds,
    const std::vector<rct::key>& E,
    const std::vector<rct::key>& T)
{
    const std::size_t n = amounts.size();
    CHECK_AND_ASSERT_THROW_MES(
        out_blinds.size() == n &&
        agg_blinds.size() == n &&
        E.size() == n &&
        T.size() == n,
        "ca::generate_UG_aggregation_proof: input vector size mismatch");
    CHECK_AND_ASSERT_THROW_MES(n > 0,
        "ca::generate_UG_aggregation_proof: empty input");

    const rct::key& U = get_U();

    UG_aggregation_proof proof;
    proof.E_prime.resize(n);
    proof.y0s.resize(n);
    proof.y1s.resize(n);

    // ------------------------------------------------------------------
    // For each output j:
    //   E'_j = e_j*U  + y'_j*G                  (aggregation commitment)
    //   D_j  = E_j - E'_j
    //        = e_j*(T_j - U) + y''_j*G           (y''_j = y_j - y'_j)
    // ------------------------------------------------------------------
    std::vector<rct::key> D(n);
    for (std::size_t j = 0; j < n; ++j) {
        // E'_j = e_j*U + y'_j*G
        proof.E_prime[j] = point_mult_plus_base(amounts[j], U, agg_blinds[j]);

        // D_j = E_j - E'_j
        rct::subKeys(D[j], E[j], proof.E_prime[j]);
    }

    // ------------------------------------------------------------------
    // Random nonces and per-output commitments R_j
    // ------------------------------------------------------------------
    rct::keyV k0(n), k1(n);
    std::vector<rct::key> R(n);

    for (std::size_t j = 0; j < n; ++j) {
        k0[j] = rct::skGen();
        k1[j] = rct::skGen();

        // TmU_j = T_j - U
        rct::key TmU;
        rct::subKeys(TmU, T[j], U);

        // R_j = k0_j*(T_j - U) + k1_j*G
        R[j] = point_mult_plus_base(k0[j], TmU, k1[j]);
    }

    // ------------------------------------------------------------------
    // Fiat-Shamir:  c = Hs(m || D_0 || ... || D_{n-1} || R_0 || ... || R_{n-1})
    // ------------------------------------------------------------------
    {
        std::vector<const rct::key*> hash_inputs;
        hash_inputs.reserve(1 + 2 * n);
        hash_inputs.push_back(&m);
        for (std::size_t j = 0; j < n; ++j) hash_inputs.push_back(&D[j]);
        for (std::size_t j = 0; j < n; ++j) hash_inputs.push_back(&R[j]);
        proof.c = fiat_shamir_vec(hash_inputs);
    }

    // ------------------------------------------------------------------
    // Responses for each output j:
    //   y0_j = k0_j - c * e_j    mod l   (for the (T_j-U) component)
    //   y1_j = k1_j - c * y''_j  mod l   (for the G component)
    //
    // where  y''_j = y_j - y'_j  (difference of G blinding factors)
    // ------------------------------------------------------------------
    for (std::size_t j = 0; j < n; ++j) {
        // y''_j = y_j - y'_j
        rct::key y_pp;
        sc_sub(y_pp.bytes, out_blinds[j].bytes, agg_blinds[j].bytes);

        // y0_j = k0_j - c*e_j
        sc_mulsub(proof.y0s[j].bytes, proof.c.bytes, amounts[j].bytes, k0[j].bytes);

        // y1_j = k1_j - c*y''_j
        sc_mulsub(proof.y1s[j].bytes, proof.c.bytes, y_pp.bytes, k1[j].bytes);
    }

    return proof;
}

bool verify_UG_aggregation_proof(
    const rct::key&              m,
    const std::vector<rct::key>& E,
    const std::vector<rct::key>& T,
    const UG_aggregation_proof&  proof) noexcept
{
    try {
        const std::size_t n = E.size();

        // Basic structural checks
        if (n == 0 ||
            proof.E_prime.size() != n ||
            proof.y0s.size()     != n ||
            proof.y1s.size()     != n ||
            T.size()             != n)
            return false;

        if (sc_check(proof.c.bytes) != 0)
            return false;

        const rct::key& U = get_U();

        // ------------------------------------------------------------------
        // For each j recompute  D_j  and  R'_j, then re-derive the challenge.
        // ------------------------------------------------------------------
        std::vector<rct::key> D(n), Rprime(n);

        for (std::size_t j = 0; j < n; ++j) {
            if (sc_check(proof.y0s[j].bytes) != 0 ||
                sc_check(proof.y1s[j].bytes) != 0)
                return false;

            // D_j = E_j - E'_j
            rct::subKeys(D[j], E[j], proof.E_prime[j]);

            // TmU_j = T_j - U
            rct::key TmU;
            rct::subKeys(TmU, T[j], U);

            // R'_j = y0_j*(T_j-U) + y1_j*G + c*D_j
            //
            // Correctness (if proof was honestly generated):
            //   y0_j*(T_j-U) + y1_j*G + c*D_j
            //   = (k0_j - c*e_j)*(T_j-U)
            //     + (k1_j - c*y''_j)*G
            //     + c*(e_j*(T_j-U) + y''_j*G)
            //   = k0_j*(T_j-U) + k1_j*G
            //   = R_j   ✓
            const rct::key t0 = rct::scalarmultKey(TmU,  proof.y0s[j]);
            const rct::key t1 = rct::scalarmultBase(proof.y1s[j]);
            const rct::key t2 = rct::scalarmultKey(D[j], proof.c);

            rct::addKeys(Rprime[j], t0, t1);
            rct::addKeys(Rprime[j], Rprime[j], t2);
        }

        // Re-derive challenge and compare
        std::vector<const rct::key*> hash_inputs;
        hash_inputs.reserve(1 + 2 * n);
        hash_inputs.push_back(&m);
        for (std::size_t j = 0; j < n; ++j) hash_inputs.push_back(&D[j]);
        for (std::size_t j = 0; j < n; ++j) hash_inputs.push_back(&Rprime[j]);

        const rct::key c_check = fiat_shamir_vec(hash_inputs);
        return (proof.c == c_check);
    }
    catch (...) {
        return false;
    }
}

} // namespace ca
