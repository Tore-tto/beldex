// Copyright (c) 2024 Beldex Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Confidential Asset (CA) on-chain data types.
//
// An asset in Beldex is identified by the crypto::hash of its
// asset_descriptor_base.  That hash is used to derive the asset-specific
// curve-point generator  Ht = compute_asset_generator(descriptor_hash)
// which is then used in all Pedersen commitments for that asset.
//
// Asset lifecycle:
//   REGISTER  – publish descriptor, establish owner, set max supply
//   EMIT      – mint new tokens (owner only, up to total_max_supply)
//   UPDATE    – change mutable metadata fields (ticker, full_name, meta_info)
//   BURN      – permanently destroy tokens, reduce current_supply

#pragma once

#include <cstdint>
#include <string>
#include "crypto/crypto.h"
#include "serialization/serialization.h"
#include "serialization/string.h"
#include "serialization/binary_utils.h"

#include "epee/serialization/keyvalue_serialization.h"

namespace cryptonote {

// ---------------------------------------------------------------------------
// Asset operation type
// ---------------------------------------------------------------------------

enum class asset_operation_type : uint8_t
{
    REGISTER = 1,  // create a new asset; burns native BDX as fee
    EMIT     = 2,  // increase current_supply (owner-signed)
    UPDATE   = 3,  // update mutable metadata (owner-signed)
    BURN     = 4,  // decrease current_supply (owner-signed)
};

// ---------------------------------------------------------------------------
// Asset descriptor
//
// Immutable after REGISTER except where noted with [mutable].
// The descriptor hash  = cn_fast_hash(serialized asset_descriptor_base)
// is used as the asset's canonical identifier on-chain.
// ---------------------------------------------------------------------------

struct asset_descriptor_base
{
    // Serialization version – increment when fields are added.
    static constexpr uint8_t CURRENT_VERSION = 1;
    uint8_t version = CURRENT_VERSION;

    // Maximum number of tokens that can ever exist (immutable).
    uint64_t total_max_supply = 0;

    // Current circulating supply – updated on EMIT/BURN.
    // Not part of the descriptor hash (changes over lifetime of asset).
    uint64_t current_supply = 0;

    // Decimal places for display (e.g. 9 for nano-units).  Immutable.
    uint8_t decimal_point = 0;

    // Short ticker symbol (e.g. "WBTC").  [mutable via UPDATE]
    std::string ticker;

    // Human-readable name (e.g. "Wrapped Bitcoin").  [mutable via UPDATE]
    std::string full_name;

    // Optional metadata: URI, JSON, or any UTF-8 string.  [mutable via UPDATE]
    std::string meta_info;

    // Public key of the asset owner.  Only this key may sign EMIT/BURN/UPDATE.
    // [mutable via UPDATE – allows ownership transfer]
    crypto::public_key owner = crypto::null_pkey;

    // If true, current_supply is not published on-chain.
    bool hidden_supply = false;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(version)
      VARINT_FIELD(total_max_supply)
      VARINT_FIELD(current_supply)
      VARINT_FIELD(decimal_point)
      FIELD(ticker)
      FIELD(full_name)
      FIELD(meta_info)
      FIELD(owner)
      FIELD(hidden_supply)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(version)
      KV_SERIALIZE(total_max_supply)
      KV_SERIALIZE(current_supply)
      KV_SERIALIZE(decimal_point)
      KV_SERIALIZE(ticker)
      KV_SERIALIZE(full_name)
      KV_SERIALIZE(meta_info)
      KV_SERIALIZE_VAL_POD_AS_BLOB(owner)
      KV_SERIALIZE(hidden_supply)
    END_KV_SERIALIZE_MAP()
};

// ---------------------------------------------------------------------------
// Compute the canonical asset id (descriptor hash).
//
// The hash covers all immutable fields.  current_supply is excluded so that
// the id remains stable across EMIT/BURN operations.
// ---------------------------------------------------------------------------
inline crypto::hash asset_descriptor_id(const asset_descriptor_base& desc)
{
    // Serialise the descriptor to bytes, then hash.
    // current_supply is skipped by constructing a temporary with it zeroed.
    asset_descriptor_base stable = desc;
    stable.current_supply = 0;   // exclude mutable supply from id

    serialization::binary_string_archiver ba;
    ::serialization::serialize(ba, stable);

    const std::string blob = ba.str();
    crypto::hash h;
    crypto::cn_fast_hash(blob.data(), blob.size(), h);
    return h;
}

// ---------------------------------------------------------------------------
// Asset emit / burn record
//
// Attached to EMIT or BURN transactions.  The amount is the delta.
// Signed by the asset owner key.
// ---------------------------------------------------------------------------
struct asset_coin_operation
{
    asset_operation_type  op_type;       // EMIT or BURN
    crypto::hash          asset_id;      // identifies the asset
    uint64_t              amount;        // tokens to mint or destroy
    crypto::signature     owner_sig;     // sig over (op_type || asset_id || amount)

    BEGIN_SERIALIZE_OBJECT()
      ENUM_FIELD(op_type, op_type == asset_operation_type::EMIT
                       || op_type == asset_operation_type::BURN)
      FIELD(asset_id)
      VARINT_FIELD(amount)
      FIELD(owner_sig)
    END_SERIALIZE()
};

} // namespace cryptonote
