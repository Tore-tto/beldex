// Copyright (c) 2026, The Beldex Project
#include "gtest/gtest.h"
#include <algorithm>
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_core/token_history_utils.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "cryptonote_basic/token_descriptor.h"
#include "ringct/rctSigs.h"
#include "ringct/rctOps.h"
#include "ringct/bulletproofs_plus.h"
#include "random_path.h"

namespace {
using namespace cryptonote;
using operation = token_descriptor_operation_type;
const operation operations[] = {operation::register_token, operation::mint_token,
    operation::update_token, operation::burn_token};
const txtype types[] = {txtype::register_privacy_token, txtype::mint_token,
    txtype::update_token, txtype::burn_token};

class TokenSecurity : public testing::Test
{
protected:
  fs::path path = random_tmp_file();
  BlockchainLMDB db;
  tx_extra_token_descriptor_operation registration{};
  crypto::token_id id{};
  const rct::key owner_secret = rct::d2h(13), mask = rct::d2h(7);

  void SetUp() override
  {
    db.open(path, FAKECHAIN);
    registration.operation_type = operation::register_token;
    registration.fields = token_field_descriptor;
    registration.descriptor.ticker = "TEST";
    registration.descriptor.full_name = "Test token";
    registration.descriptor.current_supply = 100;
    registration.descriptor.total_max_supply = 1000;
    registration.descriptor.owner = rct::rct2pk(rct::scalarmultBase(owner_secret));
    id = get_or_calculate_token_id(registration);
    db_wtxn_guard guard(&db);
    token_consensus_state seed{};
    std::string seed_reason;
    ASSERT_TRUE(apply_token_operation_to_state(id, registration, seed, seed_reason)) << seed_reason;
    static_cast<BlockchainDB&>(db).set_token_history(id, serialization::dump_binary(seed));
    guard.stop();
  }
  void TearDown() override
  {
    db.close();
    fs::remove_all(path);
  }

  // These are valid inputs to the token-state validator, not fully signed
  // spend transactions. Ring signatures/range proofs are tested separately.
  transaction make_tx(size_t kind, bool duplicate = false, bool zy_input = true,
                      bool wrong_output_commitment = false)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type = types[kind];
    auto op = registration;
    op.operation_type = operations[kind];
    if (kind == 0)
      op.descriptor.ticker = "NEW";
    else
    {
      op.token_id = id;
      op.fields |= token_field_token_id;
    }
    if (kind == 1 || kind == 3)
    {
      op.fields = token_field_token_id | token_field_amount;
      op.amount = 10;
    }
    if (kind == 3)
    {
      if (zy_input) tx.vin.emplace_back(txin_zy_input{});
      else tx.vin.emplace_back(txin_to_key{});
    }
    if (kind != 2)
    {
      const auto tid = get_or_calculate_token_id(op);
      const auto amount = kind == 0 ? op.descriptor.current_supply : op.amount;
      rct::key commitment;
      rct::addKeys(commitment, rct::scalarmultKey(rct::tid2rct(tid), rct::d2h(amount)),
                   rct::scalarmultBase(mask));
      op.fields |= token_field_amount_commitment;
      op.amount_commitment = rct::rct2pk(commitment);
      if (kind != 3)
      {
        for (size_t i = 0; i < MIN_TOKEN_MINT_OUTPUTS; ++i)
        {
          tx_out_zyphora out{};
          out.amount_commitment = rct::rct2pk(i == 0 && !wrong_output_commitment ? commitment : rct::identity());
          out.blinded_token_id = tid;
          tx.vout.push_back(tx_out{0, out});
        }
      }
    }
    if (!add_token_descriptor_operation_to_tx_extra(tx.extra, op) ||
        (duplicate && !add_token_descriptor_operation_to_tx_extra(tx.extra, op)))
      throw std::runtime_error("Cannot encode test operation");
    tx.output_unlock_times.resize(tx.vout.size());
    crypto::hash prefix;
    get_transaction_prefix_hash(tx, prefix);
    const auto msg = rct::hash2rct(prefix);
    if (kind != 2)
    {
      rct::token_operation_proof proof{};
      proof.flags = 1;
      if (!crypto::generate_linear_composition_proof(msg, rct::scalarmultBase(mask),
              mask, rct::zero(), proof.composition_proof))
        throw std::runtime_error("Cannot generate composition proof");
      tx.token_proofs.emplace_back(proof);
    }
    if (kind != 3) // register, mint and update are signed by the owner
    {
      rct::token_operation_ownership_proof proof{};
      if (!crypto::generate_schnorr_sig(msg, rct::pk2rct(registration.descriptor.owner), owner_secret, proof.sig))
        throw std::runtime_error("Cannot generate ownership proof");
      tx.token_proofs.emplace_back(proof);
    }
    return tx;
  }
  bool validate(const transaction& tx, std::string& reason)
  {
    return validate_tx_token_operations_against_db(db, tx, reason, feature::PRIVACY_TOKENS);
  }
};

TEST_F(TokenSecurity, MatchingOperationsPassAndEveryCrossTypedPairFails)
{
  std::string before;
  ASSERT_TRUE(static_cast<BlockchainDB&>(db).get_token_history(id, before));
  for (size_t op = 0; op < 4; ++op)
  {
    auto valid = make_tx(op);
    std::string reason;
    ASSERT_TRUE(validate(valid, reason)) << op << ": " << reason;
    for (size_t type = 0; type < 4; ++type)
    {
      if (type == op) continue;
      SCOPED_TRACE("operation=" + std::to_string(op) + " type=" + std::to_string(type));
      auto crossed = valid;
      crossed.type = types[type];
      EXPECT_FALSE(validate(crossed, reason));
      EXPECT_NE(reason.find("cross-typed"), std::string::npos) << reason;
      // Isolate proof-set prevalidation from unrelated signature requirements.
      crossed.token_proofs.clear();
      crossed.vin.clear();
      EXPECT_FALSE(rct::verTokenProofs(crossed, {}, {}, reason));
      EXPECT_NE(reason.find("cross-typed"), std::string::npos) << reason;
    }
  }
  std::string after;
  ASSERT_TRUE(static_cast<BlockchainDB&>(db).get_token_history(id, after));
  EXPECT_EQ(before, after);
}

TEST_F(TokenSecurity, BurnCannotUseNativeInputsToReduceTokenSupply)
{
  std::string reason;
  ASSERT_TRUE(validate(make_tx(3), reason)) << reason;
  auto tx = make_tx(3, false, false);
  EXPECT_FALSE(validate(tx, reason));
  EXPECT_NE(reason.find("must spend at least one"), std::string::npos) << reason;
  token_consensus_state state{};
  ASSERT_TRUE(load_token_state(db, id, state, reason));
  EXPECT_EQ(state.current_supply, 100);
}

// The id function itself decides, by operation type, where an id comes from:
// a register can never choose its own id, and the other operations must name
// their token explicitly rather than have it re-derived from a descriptor.
TEST_F(TokenSecurity, TokenIdSourceIsFixedByOperationType)
{
  crypto::token_id chosen{};
  chosen.data[0] = 0x42; // arbitrary attacker-picked id

  // register: an explicit id is ignored; the derived id is returned.
  auto reg = registration;
  reg.fields |= token_field_token_id;
  reg.token_id = chosen;
  EXPECT_EQ(get_or_calculate_token_id(reg), id);
  EXPECT_NE(get_or_calculate_token_id(reg), chosen);
  // ...and the operation is still rejected outright by the validator.
  std::string reason;
  EXPECT_FALSE(validate_token_descriptor_operation(reg, reason));
  EXPECT_NE(reason.find("must not carry an explicit token_id"), std::string::npos) << reason;

  for (operation type : {operation::mint_token, operation::update_token, operation::burn_token})
  {
    SCOPED_TRACE(static_cast<int>(type));
    // With the field set, the named id is used.
    auto op = registration;
    op.operation_type = type;
    op.fields = token_field_descriptor | token_field_token_id | token_field_amount;
    op.token_id = id;
    op.amount = 1;
    EXPECT_EQ(get_or_calculate_token_id(op), id);

    // Without it, the id is NOT re-derived from the embedded descriptor.
    op.fields = token_field_descriptor | token_field_amount;
    EXPECT_EQ(get_or_calculate_token_id(op), crypto::null_tid);
    EXPECT_FALSE(validate_token_descriptor_operation(op, reason));
  }

  // Undefined operation type never yields an id.
  auto undefined = registration;
  undefined.operation_type = operation::undefined;
  EXPECT_EQ(get_or_calculate_token_id(undefined), crypto::null_tid);
}

// A register must be signed by the owner named in its descriptor, over the tx
// prefix (which covers the outputs). The descriptor and salt are public once a
// register is broadcast, so the signature is what ties a token id to the
// outputs its owner chose.
TEST_F(TokenSecurity, RegisterRequiresOwnerSignatureOverThisTransaction)
{
  auto ownership = [](transaction& tx) -> rct::token_operation_ownership_proof& {
    for (auto& proof : tx.token_proofs)
      if (auto* p = std::get_if<rct::token_operation_ownership_proof>(&proof))
        return *p;
    throw std::runtime_error("no ownership proof");
  };
  auto expect_rejected = [this](const transaction& tx) {
    std::string reason;
    EXPECT_FALSE(validate(tx, reason));
    EXPECT_NE(reason.find("ownership proof for registration"), std::string::npos) << reason;
  };
  std::string reason;
  const auto valid = make_tx(0);
  ASSERT_TRUE(validate(valid, reason)) << reason;

  // No ownership proof at all.
  auto missing = valid;
  missing.token_proofs.erase(std::remove_if(missing.token_proofs.begin(), missing.token_proofs.end(),
      [](const auto& p) { return std::holds_alternative<rct::token_operation_ownership_proof>(p); }),
      missing.token_proofs.end());
  expect_rejected(missing);

  // Signed by a key other than descriptor.owner.
  crypto::hash prefix;
  get_transaction_prefix_hash(valid, prefix);
  const rct::key other_secret = rct::d2h(99);
  auto wrong_signer = valid;
  ASSERT_TRUE(crypto::generate_schnorr_sig(rct::hash2rct(prefix), rct::scalarmultBase(other_secret),
      other_secret, ownership(wrong_signer).sig));
  expect_rejected(wrong_signer);

  // The owner's signature from one register does not carry over to a tx with
  // the same descriptor but a different prefix, even when everything that
  // needs no owner key (here the amount-commitment proof) is redone for it.
  auto other_prefix = valid;
  other_prefix.output_unlock_times[0] = 1;
  get_transaction_prefix_hash(other_prefix, prefix);
  for (auto& proof : other_prefix.token_proofs)
    if (auto* p = std::get_if<rct::token_operation_proof>(&proof))
      ASSERT_TRUE(crypto::generate_linear_composition_proof(rct::hash2rct(prefix),
          rct::scalarmultBase(mask), mask, rct::zero(), p->composition_proof));
  expect_rejected(other_prefix);
}

TEST_F(TokenSecurity, EmissionCannotUseBurnCommitmentExemption)
{
  for (size_t kind : {size_t{0}, size_t{1}})
  {
    std::string reason;
    ASSERT_TRUE(validate(make_tx(kind), reason)) << reason;
    // Composition proof is valid, but the outputs do not back its amount.
    EXPECT_FALSE(validate(make_tx(kind, false, true, true), reason));
    EXPECT_NE(reason.find("do not sum"), std::string::npos) << reason;
    // A burn descriptor must not turn a mint/deploy into the burn early-return.
    auto tx = make_tx(3);
    tx.type = types[kind];
    EXPECT_FALSE(validate(tx, reason));
    EXPECT_NE(reason.find("cross-typed"), std::string::npos) << reason;
  }
}

TEST_F(TokenSecurity, DuplicateOperationsRejectedAtBothValidationLayers)
{
  for (size_t kind = 0; kind < 4; ++kind)
  {
    SCOPED_TRACE(kind);
    auto tx = make_tx(kind, true);
    std::string reason;
    EXPECT_FALSE(validate(tx, reason));
    EXPECT_NE(reason.find("exactly one"), std::string::npos) << reason;
    tx.token_proofs.clear();
    tx.vin.clear();
    EXPECT_FALSE(rct::verTokenProofs(tx, {}, {}, reason));
    EXPECT_NE(reason.find("exactly one"), std::string::npos) << reason;
  }
}

TEST_F(TokenSecurity, ReusedTransactionObjectDoesNotCarryTokenSections)
{
  // A native transaction with no privacy-token content.
  transaction native{};
  native.version = txversion::v4_tx_types;
  native.type = txtype::standard;
  txin_to_key in{};
  in.key_offsets = {1};
  native.vin.emplace_back(in);
  native.vout.push_back(tx_out{0, txout_to_key{rct::rct2pk(rct::scalarmultBase(mask))}});
  native.output_unlock_times.resize(native.vout.size());
  native.rct_signatures.type = rct::RCTType::Null;
  const std::string native_blob = serialization::dump_binary(native);

  // Parse it into an object that still holds a token transaction's
  // signatures and proofs, as happens when one object is reused per blob.
  transaction reused = make_tx(1);
  reused.zy_sig.emplace_back(rct::ZY_sig{});
  ASSERT_FALSE(reused.token_proofs.empty());

  ASSERT_NO_THROW(serialization::parse_binary(native_blob, reused));
  EXPECT_TRUE(reused.token_proofs.empty());
  EXPECT_TRUE(reused.zy_sig.empty());
  EXPECT_FALSE(tx_has_privacy_token_content(reused));
  EXPECT_EQ(serialization::dump_binary(reused), native_blob);

  // The pruned parse path must not keep them either.
  transaction reused_base = make_tx(1);
  reused_base.zy_sig.emplace_back(rct::ZY_sig{});
  serialization::binary_string_unarchiver ba{native_blob};
  ASSERT_NO_THROW(reused_base.serialize_base(ba));
  EXPECT_TRUE(reused_base.token_proofs.empty());
  EXPECT_TRUE(reused_base.zy_sig.empty());
}

TEST_F(TokenSecurity, TokenProofSetHasOneCanonicalEncoding)
{
  // Prevalidation runs before any signature or proof check, so these txs only
  // need to reach it; later steps may fail for unrelated reasons (missing
  // surjection/range proofs), which is why only the reason is inspected.
  auto prevalidation_reason = [](const transaction& tx) {
    std::string reason;
    rct::verTokenProofs(tx, {}, {}, reason);
    return reason;
  };
  auto is_layout_error = [](const std::string& reason) {
    return reason.find("canonical order") != std::string::npos ||
           reason.find("invalid flags") != std::string::npos ||
           reason.find("without zyphora inputs") != std::string::npos;
  };

  // The wallet's own layouts are accepted by the layout checks.
  for (size_t kind = 0; kind < 3; ++kind)
  {
    SCOPED_TRACE(kind);
    const std::string reason = prevalidation_reason(make_tx(kind));
    EXPECT_FALSE(is_layout_error(reason)) << reason;
  }

  // Reordering: mint carries {amount-commitment, ownership}.
  {
    auto tx = make_tx(1);
    ASSERT_EQ(tx.token_proofs.size(), 2u);
    std::swap(tx.token_proofs[0], tx.token_proofs[1]);
    EXPECT_NE(prevalidation_reason(tx).find("canonical order"), std::string::npos);
  }

  // Duplicates are rejected by the same ordering rule.
  {
    auto tx = make_tx(2);
    tx.token_proofs.push_back(tx.token_proofs.back());
    EXPECT_NE(prevalidation_reason(tx).find("canonical order"), std::string::npos);
  }

  // Undefined flag bits.
  for (uint8_t flags : {uint8_t{0}, uint8_t{3}, uint8_t{0x81}, uint8_t{0xff}})
  {
    SCOPED_TRACE(int{flags});
    auto tx = make_tx(0);
    auto* aop = std::get_if<rct::token_operation_proof>(&tx.token_proofs[0]);
    ASSERT_NE(aop, nullptr);
    aop->flags = flags;
    EXPECT_NE(prevalidation_reason(tx).find("invalid flags"), std::string::npos);
  }

  // ...and they cannot be decoded from the wire either.
  {
    auto tx = make_tx(0);
    auto proof = std::get<rct::token_operation_proof>(tx.token_proofs[0]);
    std::string blob = serialization::dump_binary(proof);
    ASSERT_EQ(static_cast<uint8_t>(blob[0]), 1);
    rct::token_operation_proof parsed{};
    ASSERT_NO_THROW(serialization::parse_binary(blob, parsed));
    blob[0] = 3;
    EXPECT_THROW(serialization::parse_binary(blob, parsed), std::exception);
  }

  // An unverified balance proof on txs without zyphora inputs.
  for (size_t kind = 0; kind < 3; ++kind)
  {
    SCOPED_TRACE(kind);
    auto tx = make_tx(kind);
    tx.token_proofs.insert(tx.token_proofs.begin(), rct::zy_balance_proof{});
    EXPECT_NE(prevalidation_reason(tx).find("without zyphora inputs"), std::string::npos);
  }
}

TEST_F(TokenSecurity, PoppingABlockAlsoRewindsItsTokenState)
{
  // Two stored blocks; token operations are applied for the top one exactly
  // as block acceptance does.
  for (uint64_t h = 0; h < 2; ++h)
  {
    block blk{};
    if (h) blk.prev_id = db.get_block_hash_from_height(h - 1);
    blk.timestamp = h;
    blk.miner_tx.version = txversion::v2_ringct;
    blk.miner_tx.vin.emplace_back(txin_gen{h});
    db_wtxn_guard guard(&db);
    db.add_block({blk, block_to_blob(blk)}, 1, 1, 1, 1, {});
    guard.stop();
  }
  ASSERT_EQ(db.height(), 2u);
  const uint64_t top_height = 1;

  const transaction registration_tx = make_tx(0); // registers a second token
  tx_extra_token_descriptor_operation new_op{};
  ASSERT_TRUE(get_token_descriptor_operation_from_tx_extra(registration_tx.extra, new_op, 0));
  const crypto::token_id new_id = get_or_calculate_token_id(new_op);
  std::string reason;
  {
    db_wtxn_guard guard(&db);
    ASSERT_TRUE(apply_tokens_from_block(db, top_height, {registration_tx, make_tx(1)}, &reason)) << reason;
    guard.stop();
  }
  token_consensus_state state{};
  ASSERT_TRUE(load_token_state(db, id, state, reason)) << reason;
  ASSERT_EQ(state.current_supply, 110u);
  ASSERT_TRUE(load_token_state(db, new_id, state, reason)) << reason;
  ASSERT_TRUE(state.exists);

  // Pop the top block the way startup does when the fork table no longer
  // matches the stored block versions.
  ASSERT_TRUE(db.batch_start());
  block popped{};
  std::vector<transaction> popped_txs;
  ASSERT_TRUE(pop_block_and_rewind_tokens(db, popped, popped_txs, &reason)) << reason;
  db.batch_stop();

  EXPECT_EQ(db.height(), 1u);
  ASSERT_TRUE(load_token_state(db, id, state, reason)) << reason;
  EXPECT_TRUE(state.exists);
  EXPECT_EQ(state.current_supply, 100u);
  ASSERT_TRUE(load_token_state(db, new_id, state, reason)) << reason;
  EXPECT_FALSE(state.exists);
  std::string undo;
  EXPECT_FALSE(static_cast<BlockchainDB&>(db).get_token_undo(top_height, undo));
}

TEST_F(TokenSecurity, BlockAllowsOneRegisterMintOrUpdatePerToken)
{
  // Each operation alone passes the per-transaction validator, which only sees
  // committed state; the block-level rule is what stops them being combined.
  std::string reason;
  for (size_t kind = 0; kind < 4; ++kind)
    ASSERT_TRUE(validate(make_tx(kind), reason)) << kind << ": " << reason;

  const size_t update = 2, mint = 1, burn = 3, reg = 0;
  // Ownership transfer followed by a mint signed by the previous owner.
  {
    std::unordered_set<crypto::token_id> seen;
    ASSERT_TRUE(check_block_token_op_exclusivity(make_tx(update), seen, reason)) << reason;
    EXPECT_FALSE(check_block_token_op_exclusivity(make_tx(mint), seen, reason));
    EXPECT_NE(reason.find("more than one"), std::string::npos) << reason;
  }
  // Every ordered pair of register/mint/update on one token is rejected.
  for (size_t first : {mint, update})
    for (size_t second : {mint, update})
    {
      SCOPED_TRACE(std::to_string(first) + "," + std::to_string(second));
      std::unordered_set<crypto::token_id> seen;
      ASSERT_TRUE(check_block_token_op_exclusivity(make_tx(first), seen, reason)) << reason;
      EXPECT_FALSE(check_block_token_op_exclusivity(make_tx(second), seen, reason));
    }
  // Burn is exempt, as in the mempool, and a different token is unaffected.
  {
    std::unordered_set<crypto::token_id> seen;
    ASSERT_TRUE(check_block_token_op_exclusivity(make_tx(mint), seen, reason)) << reason;
    EXPECT_TRUE(check_block_token_op_exclusivity(make_tx(burn), seen, reason)) << reason;
    EXPECT_TRUE(check_block_token_op_exclusivity(make_tx(burn), seen, reason)) << reason;
    EXPECT_TRUE(check_block_token_op_exclusivity(make_tx(reg), seen, reason)) << reason;
  }
  // A native transaction carries no token operation.
  {
    std::unordered_set<crypto::token_id> seen;
    transaction native{};
    native.version = txversion::v4_tx_types;
    native.type = txtype::standard;
    EXPECT_TRUE(check_block_token_op_exclusivity(native, seen, reason)) << reason;
    EXPECT_TRUE(seen.empty());
  }
}

TEST_F(TokenSecurity, MetaInfoMustBeUtf8)
{
  std::string error;
  auto d = registration.descriptor;
  for (const std::string ok : {std::string{""}, std::string{"Website: priv.io, Telegram: @priv"},
                               std::string{"\xe0\xae\xb5\xe0\xae\xa3\xe0\xae\x95\xe0\xaf\x8d\xe0\xae\x95\xe0\xae\xae\xe0\xaf\x8d"},
                               std::string{"\xf0\x9f\x9a\x80"}})
  {
    d.meta_info = ok;
    EXPECT_TRUE(validate_token_descriptor_for_registration(d, error)) << error;
  }
  // Raw bytes, an overlong '/', a UTF-16 surrogate, a code point past U+10FFFF
  // and a truncated sequence.
  for (const std::string bad : {std::string{"bad \xff\xfe bytes"}, std::string{"\xc0\xaf"},
                                std::string{"\xed\xa0\x80"}, std::string{"\xf4\x90\x80\x80"},
                                std::string{"\xe2\x82"}})
  {
    d.meta_info = bad;
    EXPECT_FALSE(validate_token_descriptor_for_registration(d, error));
    EXPECT_NE(error.find("UTF-8"), std::string::npos) << error;
  }

  // The same rule binds an update, which replaces meta_info on chain.
  token_consensus_state state{};
  std::string reason;
  ASSERT_TRUE(apply_token_operation_to_state(id, registration, state, reason)) << reason;
  auto update = registration;
  update.operation_type = operation::update_token;
  update.fields |= token_field_token_id;
  update.token_id = id;
  update.descriptor.meta_info = "bad \xff\xfe bytes";
  EXPECT_FALSE(apply_token_operation_to_state(id, update, state, reason));
  EXPECT_NE(reason.find("UTF-8"), std::string::npos) << reason;
}

TEST_F(TokenSecurity, OperationsCarryOnlyTheirOwnFields)
{
  // The wallet's layouts are accepted.
  std::string reason;
  for (size_t kind = 0; kind < 4; ++kind)
    ASSERT_TRUE(validate(make_tx(kind), reason)) << kind << ": " << reason;

  auto check = [](tx_extra_token_descriptor_operation op) {
    std::string reason;
    EXPECT_FALSE(validate_token_descriptor_operation(op, reason));
    EXPECT_NE(reason.find("does not use"), std::string::npos) << reason;
  };
  auto mint_like = [this](operation type) {
    tx_extra_token_descriptor_operation op{};
    op.operation_type = type;
    op.fields = token_field_token_id | token_field_amount;
    op.token_id = id;
    op.amount = 1;
    return op;
  };

  // A descriptor riding along on a mint or burn, e.g. advertising another
  // token's ticker, or a salt that only a registration uses.
  for (operation type : {operation::mint_token, operation::burn_token})
  {
    SCOPED_TRACE(static_cast<int>(type));
    auto op = mint_like(type);
    op.fields |= token_field_descriptor;
    op.descriptor = registration.descriptor;
    op.descriptor.ticker = "BDX";
    check(op);
    op = mint_like(type);
    op.fields |= token_field_token_id_salt;
    check(op);
  }
  // An update has no amount or commitment.
  {
    auto op = registration;
    op.operation_type = operation::update_token;
    op.fields |= token_field_token_id | token_field_amount;
    op.token_id = id;
    op.amount = 1;
    check(op);
  }
  // A registration has no amount (its supply is in the descriptor).
  {
    auto op = registration;
    op.fields |= token_field_amount;
    op.amount = 1;
    check(op);
  }
// A tx with token outputs may have at most TX_BULLETPROOF_PLUS_MAX_OUTPUTS
// outputs in total, native and token together.
TEST(TokenOutputLimit, TooManyOutputsRejectedBeforeAnyProofIsRead)
{
  const size_t max = TX_BULLETPROOF_PLUS_MAX_OUTPUTS;
  auto make = [](size_t native, size_t token) {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type = txtype::standard;
    tx.vout.assign(native, tx_out{0, txout_to_key{}});
    tx.vout.insert(tx.vout.end(), token, tx_out{0, tx_out_zyphora{}});
    return tx;
  };
  auto over_limit = [](const transaction& tx) {
    std::string reason;
    EXPECT_FALSE(rct::verTokenProofs(tx, {}, {}, reason)); // no proofs: fails either way
    return reason.find("too many outputs") != std::string::npos;
  };
  EXPECT_TRUE(over_limit(make(0, max + 1)));
  EXPECT_TRUE(over_limit(make(2, max - 1)));  // each kind is under the limit, the total is not
  EXPECT_TRUE(over_limit(make(max, 1)));
  EXPECT_FALSE(over_limit(make(0, max)));
  EXPECT_FALSE(over_limit(make(2, max - 2)));
}

// The verifier itself refuses a proof over more commitments than its generator
// tables cover, whoever the caller is.
TEST(TokenOutputLimit, BulletproofPlusVerifierBoundsCommitmentCount)
{
  const size_t n = TX_BULLETPROOF_PLUS_MAX_OUTPUTS;
  std::vector<uint64_t> amounts(n, 1);
  rct::keyV masks(n);
  for (auto& m : masks) m = rct::skGen();
  auto proof = rct::bulletproof_plus_PROVE(amounts, masks);
  ASSERT_TRUE(rct::bulletproof_plus_VERIFY(proof));

  // One more commitment, with the extra round such a proof would declare.
  proof.V.push_back(proof.V.front());
  proof.L.push_back(proof.L.front());
  proof.R.push_back(proof.R.front());
  EXPECT_FALSE(rct::bulletproof_plus_VERIFY(proof));
}

// The weight of a pruned token tx must be computable: token inputs may come
// first, and token outputs do not count towards the native range proof.
TEST(TokenOutputLimit, PrunedWeightHandlesTokenInputsAndOutputs)
{
  transaction tx{};
  tx.version = txversion::v4_tx_types;
  tx.type = txtype::standard;
  tx.vin.emplace_back(txin_zy_input{{1, 2, 3}, {}});
  txin_to_key native_in{};
  native_in.key_offsets.assign(10, 1);
  tx.vin.emplace_back(native_in);
  for (size_t i = 0; i < 3; ++i) // pads the native proof to 4
    tx.vout.push_back(tx_out{0, txout_to_key{}});
  for (size_t i = 3; i < TX_BULLETPROOF_PLUS_MAX_OUTPUTS; ++i)
    tx.vout.push_back(tx_out{0, tx_out_zyphora{}});
  tx.output_unlock_times.resize(tx.vout.size());
  tx.rct_signatures.type = rct::RCTType::BulletproofPlus;
  tx.rct_signatures.ecdhInfo.resize(3);
  tx.rct_signatures.outPk.resize(3);
  tx.pruned = true;

  uint64_t weight = 0;
  ASSERT_NO_THROW(weight = get_pruned_transaction_weight(tx));
  EXPECT_NE(weight, std::numeric_limits<uint64_t>::max());
  EXPECT_GT(weight, serialization::dump_binary(tx).size());

  // More native outputs than the native proof allows is reported, not thrown.
  for (size_t i = 0; i < TX_BULLETPROOF_MAX_OUTPUTS; ++i)
    tx.vout.push_back(tx_out{0, txout_to_key{}});
  tx.output_unlock_times.resize(tx.vout.size());
  tx.rct_signatures.ecdhInfo.resize(3 + TX_BULLETPROOF_MAX_OUTPUTS);
  tx.rct_signatures.outPk.resize(3 + TX_BULLETPROOF_MAX_OUTPUTS);
  EXPECT_NO_THROW(weight = get_pruned_transaction_weight(tx));
  EXPECT_EQ(weight, std::numeric_limits<uint64_t>::max());
}
} // namespace
