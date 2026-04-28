// Copyright (c) 2024 Beldex Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Confidential Assets (CA) cryptographic primitives for Beldex.
//
// Based on Zano's Zarcanum scheme:
//   https://github.com/hyle-team/zano
//   "Zano: confidential assets scheme" by sowle, Oct 2022
//
// This file provides:
//   1.  NUMS generator points X and U
//   2.  Per-asset curve-point generator   Ht = Hp(He(descriptor))
//   3.  Blinded asset tag operations      T  = Ht + r*X
//   4.  Schnorr proof over generator X    (used inside surjection proof)
//   5.  Double Schnorr / balance proof    Balance = r*X + y*G
//   6.  Vector UG aggregation proof       (links asset-specific E_j to
//                                          fixed-generator E'_j for BP+)
//
// Type conventions (Beldex / Monero style):
//   rct::key  – 32-byte value used for both compressed curve points and scalars
//   ge_p3     – extended coordinates, used for intermediate computation
//   All scalar arithmetic uses sc_* functions from crypto-ops.h

#pragma once

#include <vector>
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"

namespace ca {

// ---------------------------------------------------------------------------
// 1.  NUMS generator points
// ---------------------------------------------------------------------------

// X – Nothing-Up-My-Sleeve point with no known DL relation to G or H.
// Used in blinded asset tags:  T = Ht + r*X
// Derived as:  8 * Elligator( cn_fast_hash( cn_fast_hash("Beldex CA X v1") ) )
const rct::key& get_X();

// U – NUMS point with no known DL relation to G, H, or X.
// Used in aggregation commitments:  E' = e*U + y'*G
// Derived as:  8 * Elligator( cn_fast_hash( cn_fast_hash("Beldex CA U v1") ) )
const rct::key& get_U();

// ---------------------------------------------------------------------------
// 2.  Per-asset generator
// ---------------------------------------------------------------------------

// Compute the asset-specific generator from the asset descriptor hash:
//   Ht = 8 * Elligator( cn_fast_hash( cn_fast_hash(asset_descriptor_hash) ) )
//
// The double hash provides a pre-image separation layer; callers may cache
// the result because it is stable for the lifetime of an asset.
rct::key compute_asset_generator(const crypto::hash& asset_descriptor_hash);

// ---------------------------------------------------------------------------
// 3.  Blinded asset tag operations
// ---------------------------------------------------------------------------

// Compute blinded asset tag:  T = Ht + r*X
//
// The blinding scalar r should be derived pseudo-randomly from a shared
// secret known only to sender and receiver:
//   r = hash_to_scalar("ca_asset_tag_mask" || derivation || output_index)
rct::key blind_asset_tag(const rct::key& Ht, const rct::key& r);

// Recover the asset generator from a blinded tag:  Ht = T - r*X
rct::key unblind_asset_tag(const rct::key& T, const rct::key& r);

// ---------------------------------------------------------------------------
// 4.  Schnorr proof over generator X
//     Proves knowledge of secret x  such that  A = x * X
// ---------------------------------------------------------------------------

struct schnorr_sig_X
{
    rct::key c;  // Fiat-Shamir challenge  c = Hs(m || A || R)
    rct::key y;  // response               y = k - c*x  mod l
};

// Generate proof.  Precondition: A == x*X.
schnorr_sig_X generate_schnorr_X(
    const rct::key& m,   // message / transcript binding
    const rct::key& A,   // public point  A = x*X
    const rct::key& x);  // secret scalar

// Verify proof.  Returns true iff the proof is valid.
bool verify_schnorr_X(
    const rct::key& m,
    const rct::key& A,
    const schnorr_sig_X& sig) noexcept;

// ---------------------------------------------------------------------------
// 5.  Double Schnorr / balance proof
//     Proves knowledge of (r, y)  such that  Balance = r*X + y*G
//
// In a confidential-asset transaction the verifier computes:
//   Balance = Σ pseudo_out_commitments  −  Σ output_commitments  −  fee*H
// and the prover shows this equals r*X + y*G for known r, y.
// ---------------------------------------------------------------------------

struct double_schnorr_sig
{
    rct::key c;   // Fiat-Shamir challenge
    rct::key y0;  // response for X component:  y0 = k0 - c*r  mod l
    rct::key y1;  // response for G component:  y1 = k1 - c*y  mod l
};

// Generate balance proof.  Precondition: Balance == r*X + y*G.
double_schnorr_sig generate_balance_proof(
    const rct::key& m,        // transcript hash
    const rct::key& Balance,  // public point
    const rct::key& r,        // secret: X component
    const rct::key& y);       // secret: G component

// Verify balance proof.
bool verify_balance_proof(
    const rct::key& m,
    const rct::key& Balance,
    const double_schnorr_sig& sig) noexcept;

// ---------------------------------------------------------------------------
// 6.  Vector UG aggregation proof
//
// A transaction with k outputs uses per-asset generators T_j in its output
// commitments.  Standard Bulletproofs+ requires a single fixed generator for
// all outputs being aggregated.  This proof bridges the two:
//
//   E_j  = e_j * T_j + y_j * G      (on-chain commitment, T_j asset-specific)
//   E'_j = e_j * U  + y'_j * G      (aggregation commitment, U fixed)
//
// The proof shows, for each j:
//   D_j = E_j - E'_j = e_j*(T_j - U) + y''_j*G   (y''_j = y_j - y'_j)
//
// This lets the verifier run BP+ over {E'_j} (same generator U) and check
// the linking via {D_j}.
// ---------------------------------------------------------------------------

struct UG_aggregation_proof
{
    // E'_j = e_j*U + y'_j*G, one per output (included so verifier can
    // recompute D_j = E_j - E'_j and run BP+ on E'_j).
    std::vector<rct::key> E_prime;

    rct::key   c;    // shared Fiat-Shamir challenge
    rct::keyV  y0s;  // per-output response for (T_j - U) component
    rct::keyV  y1s;  // per-output response for G component
};

// Generate aggregation proof.
//
// Inputs (all vectors must have the same length k = number of outputs):
//   amounts      – secret amounts  e_j  as reduced scalars
//   out_blinds   – blinding factors  y_j  of the output commitments E_j
//   agg_blinds   – freshly-chosen random blinding factors  y'_j  for E'_j
//   E            – output commitments  E_j = e_j*T_j + y_j*G
//   T            – blinded asset tags  T_j  (one per output)
UG_aggregation_proof generate_UG_aggregation_proof(
    const rct::key&            m,
    const rct::keyV&           amounts,
    const rct::keyV&           out_blinds,
    const rct::keyV&           agg_blinds,
    const std::vector<rct::key>& E,
    const std::vector<rct::key>& T);

// Verify aggregation proof.
bool verify_UG_aggregation_proof(
    const rct::key&              m,
    const std::vector<rct::key>& E,   // output commitments
    const std::vector<rct::key>& T,   // blinded asset tags
    const UG_aggregation_proof&  proof) noexcept;

} // namespace ca
