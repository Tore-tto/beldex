// Copyright (c) 2026, The Beldex Project

// Makes Blockchain's coinbase pre-checks callable from this test (see blockchain.h).
#define IN_UNIT_TESTS

#include "gtest/gtest.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/uptime_proof.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "ringct/rctOps.h"
#include "random_path.h"

namespace {
using namespace cryptonote;

class TokenCoinbase : public testing::Test
{
protected:
  static constexpr uint64_t height = 100;
  fs::path path = random_tmp_file();
  tx_memory_pool pool{chain};
  master_nodes::master_node_list nodes{chain};
  Blockchain chain{pool, nodes};
  std::vector<hard_fork> saved_forks;

  void SetUp() override
  {
    saved_forks = fakechain_hardforks;
    auto* db = new BlockchainLMDB; // Owned by chain after init.
    db->open(path, FAKECHAIN);
    block genesis{};
    generate_genesis_block(genesis, FAKECHAIN);
    {
      db_wtxn_guard guard(db);
      db->add_block({genesis, block_to_blob(genesis)}, 1, 1, 1, 1, {});
      guard.stop();
    }
    const test_options options{{{hf::hf1, 0, 0, 0}}, 0};
    ASSERT_TRUE(chain.init(db, nullptr, FAKECHAIN, true, &options));
    ASSERT_TRUE(pool.init(0));
  }
  void TearDown() override
  {
    chain.deinit();
    fakechain_hardforks = saved_forks;
    fs::remove_all(path);
  }

  // A coinbase that satisfies every structural pre-check: miner, master node and governance
  // outputs, all plain key outputs.
  static block coinbase_block(hf version)
  {
    block blk{};
    auto& tx = blk.miner_tx;
    tx.version = transaction::get_max_version_for_hf(version);
    tx.type = txtype::standard;
    tx.unlock_time = height + MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.emplace_back(txin_gen{height});
    for (uint64_t i = 1; i <= 3; ++i)
      tx.vout.push_back(tx_out{i, txout_to_key{rct::rct2pk(rct::scalarmultBase(rct::d2h(i)))}});
    tx.output_unlock_times.assign(tx.vout.size(), tx.unlock_time);
    return blk;
  }
  static tx_out_zyphora token_output()
  {
    tx_out_zyphora out{};
    out.stealth_address = rct::rct2pk(rct::scalarmultBase(rct::d2h(11)));
    out.amount_commitment = rct::rct2pk(rct::scalarmultH(rct::d2h(13)));
    out.blinded_token_id = rct::rct2tid(rct::scalarmultX(rct::d2h(17)));
    return out;
  }
};

// A coinbase carries no proofs, so every output must be a plain txout_to_key whose commitment the
// node derives from the visible amount. Any other target would be stored with a commitment nobody
// proved. The rule has no fork gate, so it must hold on both sides of the privacy-token fork.
TEST_F(TokenCoinbase, PrevalidationRejectsNonKeyOutputs)
{
  const std::pair<const char*, txout_target_v> targets[] = {
      {"token", token_output()}, {"script", txout_to_script{}}, {"scripthash", txout_to_scripthash{}}};
  for (hf version : {hf::hf17_POS, hf::hf20_bulletproof_plus, feature::PRIVACY_TOKENS})
  {
    const auto good = coinbase_block(version);
    // Control: with key outputs only the same coinbase passes, so each rejection below is caused
    // by the output target alone.
    ASSERT_TRUE(chain.prevalidate_miner_transaction(good, height, version))
        << "hf=" << static_cast<int>(version);
    for (const auto& [name, target] : targets)
      for (size_t position = 0; position < good.miner_tx.vout.size(); ++position)
      {
        SCOPED_TRACE("hf=" + std::to_string(static_cast<int>(version)) + " target=" + name +
                     " position=" + std::to_string(position));
        auto bad = good;
        bad.miner_tx.vout[position].target = target;
        EXPECT_FALSE(chain.prevalidate_miner_transaction(bad, height, version));
      }
  }
}
} // namespace
