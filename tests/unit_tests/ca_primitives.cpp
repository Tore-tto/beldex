// Copyright (c) 2024 Beldex Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for src/ringct/ca_primitives.{h,cpp}

#include "gtest/gtest.h"

#include "ringct/ca_primitives.h"
#include "ringct/rctOps.h"
#include "crypto/crypto.h"

extern "C" {
#include "crypto/crypto-ops.h"
}

// ============================================================================
// Helpers
// ============================================================================

namespace {

// Build a dummy 32-byte scalar from a small integer (for deterministic tests)
rct::key scalar_from_int(uint64_t v)
{
    rct::key k = rct::zero();
    k.bytes[0] = static_cast<unsigned char>(v & 0xFF);
    k.bytes[1] = static_cast<unsigned char>((v >> 8) & 0xFF);
    k.bytes[2] = static_cast<unsigned char>((v >> 16) & 0xFF);
    k.bytes[3] = static_cast<unsigned char>((v >> 24) & 0xFF);
    sc_reduce32(k.bytes);   // ensure canonical
    return k;
}

// Generate a random reduced scalar (thin wrapper)
rct::key rand_scalar() { return rct::skGen(); }

// Build a random asset descriptor hash
crypto::hash rand_asset_hash()
{
    crypto::hash h;
    crypto::rand(sizeof(h), reinterpret_cast<uint8_t*>(&h));
    return h;
}

} // namespace

// ============================================================================
// Generator tests
// ============================================================================

TEST(CA_Generators, X_is_deterministic)
{
    // get_X() should return the same value on every call
    const rct::key& x1 = ca::get_X();
    const rct::key& x2 = ca::get_X();
    EXPECT_EQ(x1, x2);
}

TEST(CA_Generators, U_is_deterministic)
{
    const rct::key& u1 = ca::get_U();
    const rct::key& u2 = ca::get_U();
    EXPECT_EQ(u1, u2);
}

TEST(CA_Generators, X_and_U_are_distinct)
{
    EXPECT_NE(ca::get_X(), ca::get_U());
}

TEST(CA_Generators, X_not_equal_to_G)
{
    // rct::G is the Ed25519 basepoint compressed
    EXPECT_NE(ca::get_X(), rct::G);
}

TEST(CA_Generators, U_not_equal_to_G)
{
    EXPECT_NE(ca::get_U(), rct::G);
}

TEST(CA_Generators, X_in_prime_order_subgroup)
{
    // isInMainSubgroup checks that l*P == identity
    EXPECT_TRUE(rct::isInMainSubgroup(ca::get_X()));
}

TEST(CA_Generators, U_in_prime_order_subgroup)
{
    EXPECT_TRUE(rct::isInMainSubgroup(ca::get_U()));
}

// ============================================================================
// Asset generator tests
// ============================================================================

TEST(CA_AssetGenerator, deterministic_for_same_descriptor)
{
    const crypto::hash h = rand_asset_hash();
    const rct::key Ht1 = ca::compute_asset_generator(h);
    const rct::key Ht2 = ca::compute_asset_generator(h);
    EXPECT_EQ(Ht1, Ht2);
}

TEST(CA_AssetGenerator, different_descriptors_give_different_generators)
{
    const crypto::hash h1 = rand_asset_hash();
    crypto::hash h2 = h1;
    h2.data[0] ^= 0x01;    // flip one bit

    EXPECT_NE(ca::compute_asset_generator(h1), ca::compute_asset_generator(h2));
}

TEST(CA_AssetGenerator, result_in_prime_order_subgroup)
{
    const crypto::hash h = rand_asset_hash();
    const rct::key Ht = ca::compute_asset_generator(h);
    EXPECT_TRUE(rct::isInMainSubgroup(Ht));
}

// ============================================================================
// Blinded asset tag tests
// ============================================================================

TEST(CA_BlindedTag, round_trip)
{
    const crypto::hash h   = rand_asset_hash();
    const rct::key    Ht   = ca::compute_asset_generator(h);
    const rct::key    r    = rand_scalar();

    const rct::key T        = ca::blind_asset_tag(Ht, r);
    const rct::key Ht_back  = ca::unblind_asset_tag(T, r);

    EXPECT_EQ(Ht, Ht_back);
}

TEST(CA_BlindedTag, different_masks_give_different_tags)
{
    const crypto::hash h = rand_asset_hash();
    const rct::key Ht   = ca::compute_asset_generator(h);
    const rct::key r1   = rand_scalar();
    rct::key r2         = rand_scalar();
    // guarantee r1 != r2
    while (r2 == r1) r2 = rand_scalar();

    EXPECT_NE(ca::blind_asset_tag(Ht, r1), ca::blind_asset_tag(Ht, r2));
}

TEST(CA_BlindedTag, wrong_mask_does_not_unblind)
{
    const crypto::hash h = rand_asset_hash();
    const rct::key Ht   = ca::compute_asset_generator(h);
    const rct::key r    = rand_scalar();
    const rct::key r_bad = rand_scalar();

    const rct::key T        = ca::blind_asset_tag(Ht, r);
    const rct::key Ht_wrong = ca::unblind_asset_tag(T, r_bad);

    // With overwhelming probability, a random wrong mask gives the wrong point
    if (r != r_bad)
        EXPECT_NE(Ht, Ht_wrong);
}

// ============================================================================
// Schnorr proof over X
// ============================================================================

TEST(CA_SchnorrX, valid_proof_verifies)
{
    const rct::key x = rand_scalar();
    const rct::key A = rct::scalarmultKey(ca::get_X(), x);
    const rct::key m = rand_scalar();   // use a random scalar as message

    const ca::schnorr_sig_X sig = ca::generate_schnorr_X(m, A, x);
    EXPECT_TRUE(ca::verify_schnorr_X(m, A, sig));
}

TEST(CA_SchnorrX, wrong_message_fails)
{
    const rct::key x = rand_scalar();
    const rct::key A = rct::scalarmultKey(ca::get_X(), x);
    const rct::key m = rand_scalar();

    const ca::schnorr_sig_X sig = ca::generate_schnorr_X(m, A, x);

    rct::key m_bad = rand_scalar();
    while (m_bad == m) m_bad = rand_scalar();

    EXPECT_FALSE(ca::verify_schnorr_X(m_bad, A, sig));
}

TEST(CA_SchnorrX, wrong_public_key_fails)
{
    const rct::key x = rand_scalar();
    const rct::key A = rct::scalarmultKey(ca::get_X(), x);
    const rct::key m = rand_scalar();

    const ca::schnorr_sig_X sig = ca::generate_schnorr_X(m, A, x);

    // A different key
    const rct::key x2  = rand_scalar();
    const rct::key A2  = rct::scalarmultKey(ca::get_X(), x2);

    EXPECT_FALSE(ca::verify_schnorr_X(m, A2, sig));
}

TEST(CA_SchnorrX, mutated_signature_fails)
{
    const rct::key x = rand_scalar();
    const rct::key A = rct::scalarmultKey(ca::get_X(), x);
    const rct::key m = rand_scalar();

    ca::schnorr_sig_X sig = ca::generate_schnorr_X(m, A, x);

    // Flip a bit in the response scalar
    sig.y.bytes[0] ^= 0x01;
    sc_reduce32(sig.y.bytes);   // keep it canonical so sc_check passes

    EXPECT_FALSE(ca::verify_schnorr_X(m, A, sig));
}

// ============================================================================
// Double Schnorr / balance proof
// ============================================================================

// Helper: compute Balance = r*X + y*G
static rct::key make_balance(const rct::key& r, const rct::key& y)
{
    const rct::key rX = rct::scalarmultKey(ca::get_X(), r);
    const rct::key yG = rct::scalarmultBase(y);
    return rct::addKeys(rX, yG);
}

TEST(CA_BalanceProof, valid_proof_verifies)
{
    const rct::key r = rand_scalar();
    const rct::key y = rand_scalar();
    const rct::key B = make_balance(r, y);
    const rct::key m = rand_scalar();

    const ca::double_schnorr_sig sig = ca::generate_balance_proof(m, B, r, y);
    EXPECT_TRUE(ca::verify_balance_proof(m, B, sig));
}

TEST(CA_BalanceProof, wrong_message_fails)
{
    const rct::key r = rand_scalar();
    const rct::key y = rand_scalar();
    const rct::key B = make_balance(r, y);
    const rct::key m = rand_scalar();

    const ca::double_schnorr_sig sig = ca::generate_balance_proof(m, B, r, y);

    rct::key m_bad = rand_scalar();
    while (m_bad == m) m_bad = rand_scalar();

    EXPECT_FALSE(ca::verify_balance_proof(m_bad, B, sig));
}

TEST(CA_BalanceProof, wrong_balance_point_fails)
{
    const rct::key r = rand_scalar();
    const rct::key y = rand_scalar();
    const rct::key B = make_balance(r, y);
    const rct::key m = rand_scalar();

    const ca::double_schnorr_sig sig = ca::generate_balance_proof(m, B, r, y);

    // A randomly different balance point
    const rct::key B_bad = make_balance(rand_scalar(), rand_scalar());
    EXPECT_FALSE(ca::verify_balance_proof(m, B_bad, sig));
}

TEST(CA_BalanceProof, zero_balance_verifies)
{
    // r = 0, y = 0  →  Balance = identity point
    const rct::key r = rct::zero();
    const rct::key y = rct::zero();
    // 0*X + 0*G = identity
    const rct::key B = rct::identity();
    const rct::key m = rand_scalar();

    const ca::double_schnorr_sig sig = ca::generate_balance_proof(m, B, r, y);
    EXPECT_TRUE(ca::verify_balance_proof(m, B, sig));
}

// ============================================================================
// Vector UG aggregation proof
// ============================================================================

namespace {

struct OutputSet
{
    rct::keyV  amounts;
    rct::keyV  out_blinds;
    rct::keyV  agg_blinds;
    std::vector<rct::key> Ht;  // asset generators (one per output)
    std::vector<rct::key> T;   // blinded asset tags
    std::vector<rct::key> E;   // output commitments  E_j = e_j*T_j + y_j*G
    rct::key m;                // message
};

// Build an honest output set of size n, all using the same asset type
OutputSet make_output_set(std::size_t n)
{
    OutputSet os;
    os.m = rand_scalar();

    crypto::hash desc = rand_asset_hash();
    const rct::key Ht = ca::compute_asset_generator(desc);

    for (std::size_t j = 0; j < n; ++j) {
        const rct::key e   = scalar_from_int(j + 1);   // non-zero amounts
        const rct::key y   = rand_scalar();
        const rct::key r   = rand_scalar();             // asset-tag mask
        const rct::key T_j = ca::blind_asset_tag(Ht, r);
        const rct::key y_p = rand_scalar();             // agg blinding

        // E_j = e_j * T_j + y_j * G
        const rct::key eT  = rct::scalarmultKey(T_j, e);
        const rct::key yG  = rct::scalarmultBase(y);
        rct::key E_j;
        rct::addKeys(E_j, eT, yG);

        os.amounts.push_back(e);
        os.out_blinds.push_back(y);
        os.agg_blinds.push_back(y_p);
        os.Ht.push_back(Ht);
        os.T.push_back(T_j);
        os.E.push_back(E_j);
    }
    return os;
}

} // namespace

TEST(CA_UGAggregation, single_output_verifies)
{
    OutputSet os = make_output_set(1);

    const auto proof = ca::generate_UG_aggregation_proof(
        os.m, os.amounts, os.out_blinds, os.agg_blinds, os.E, os.T);

    EXPECT_TRUE(ca::verify_UG_aggregation_proof(os.m, os.E, os.T, proof));
}

TEST(CA_UGAggregation, two_outputs_verify)
{
    OutputSet os = make_output_set(2);

    const auto proof = ca::generate_UG_aggregation_proof(
        os.m, os.amounts, os.out_blinds, os.agg_blinds, os.E, os.T);

    EXPECT_TRUE(ca::verify_UG_aggregation_proof(os.m, os.E, os.T, proof));
}

TEST(CA_UGAggregation, four_outputs_verify)
{
    OutputSet os = make_output_set(4);

    const auto proof = ca::generate_UG_aggregation_proof(
        os.m, os.amounts, os.out_blinds, os.agg_blinds, os.E, os.T);

    EXPECT_TRUE(ca::verify_UG_aggregation_proof(os.m, os.E, os.T, proof));
}

TEST(CA_UGAggregation, wrong_message_fails)
{
    OutputSet os = make_output_set(2);

    const auto proof = ca::generate_UG_aggregation_proof(
        os.m, os.amounts, os.out_blinds, os.agg_blinds, os.E, os.T);

    rct::key m_bad = rand_scalar();
    while (m_bad == os.m) m_bad = rand_scalar();

    EXPECT_FALSE(ca::verify_UG_aggregation_proof(m_bad, os.E, os.T, proof));
}

TEST(CA_UGAggregation, tampered_E_prime_fails)
{
    OutputSet os = make_output_set(2);

    auto proof = ca::generate_UG_aggregation_proof(
        os.m, os.amounts, os.out_blinds, os.agg_blinds, os.E, os.T);

    // Flip a byte in the first aggregation commitment
    proof.E_prime[0].bytes[5] ^= 0xFF;

    EXPECT_FALSE(ca::verify_UG_aggregation_proof(os.m, os.E, os.T, proof));
}

TEST(CA_UGAggregation, tampered_response_scalar_fails)
{
    OutputSet os = make_output_set(2);

    auto proof = ca::generate_UG_aggregation_proof(
        os.m, os.amounts, os.out_blinds, os.agg_blinds, os.E, os.T);

    // Corrupt the first y0 response and re-reduce to keep it canonical
    proof.y0s[0].bytes[0] ^= 0x01;
    sc_reduce32(proof.y0s[0].bytes);

    EXPECT_FALSE(ca::verify_UG_aggregation_proof(os.m, os.E, os.T, proof));
}

TEST(CA_UGAggregation, wrong_output_commitment_fails)
{
    OutputSet os = make_output_set(2);

    const auto proof = ca::generate_UG_aggregation_proof(
        os.m, os.amounts, os.out_blinds, os.agg_blinds, os.E, os.T);

    // Substitute a random point for E[0]
    std::vector<rct::key> E_bad = os.E;
    E_bad[0] = rct::scalarmultBase(rand_scalar());

    EXPECT_FALSE(ca::verify_UG_aggregation_proof(os.m, E_bad, os.T, proof));
}

TEST(CA_UGAggregation, empty_input_fails_gracefully)
{
    ca::UG_aggregation_proof empty_proof;
    std::vector<rct::key> empty_vec;
    const rct::key m = rand_scalar();

    EXPECT_FALSE(ca::verify_UG_aggregation_proof(m, empty_vec, empty_vec, empty_proof));
}

// ============================================================================
// Cross-primitive consistency checks
// ============================================================================

TEST(CA_Consistency, blind_tag_is_not_native_generator)
{
    // A blinded tag should not accidentally equal H (native coin generator)
    const crypto::hash h  = rand_asset_hash();
    const rct::key    Ht  = ca::compute_asset_generator(h);
    const rct::key    r   = rand_scalar();
    const rct::key    T   = ca::blind_asset_tag(Ht, r);

    // rct::H is the standard Pedersen commitment generator
    EXPECT_NE(T, rct::H);
}

TEST(CA_Consistency, schnorr_X_proof_does_not_verify_over_G)
{
    // A Schnorr proof generated for A = x*X must not verify if we
    // replace A with x*G (different generator)
    const rct::key x = rand_scalar();
    const rct::key A_X = rct::scalarmultKey(ca::get_X(), x);
    const rct::key A_G = rct::scalarmultBase(x);
    const rct::key m   = rand_scalar();

    const ca::schnorr_sig_X sig = ca::generate_schnorr_X(m, A_X, x);

    // Passing A_G (= x*G ≠ x*X with overwhelming probability) should fail
    if (A_X != A_G)
        EXPECT_FALSE(ca::verify_schnorr_X(m, A_G, sig));
}
