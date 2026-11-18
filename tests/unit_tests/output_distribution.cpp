// Copyright (c) 2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"
#include "epee/misc_log_ex.h"
#include "rpc/core_rpc_server.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/uptime_proof.h"
#include "blockchain_db/testdb.h"

#include "blockchain_utilities/blockchain_objects.h"
#include "cryptonote_core/master_node_list.h"
#include "cryptonote_core/master_node_voting.h"

static const uint64_t test_distribution[32] = {
  0, 0, 0, 0, 0, 1, 5, 1, 4, 0, 0, 1, 0, 1, 2, 3, 1, 0, 2, 0, 1, 3, 8, 1, 3, 5, 7, 1, 5, 0, 2, 3
};
static const size_t test_distribution_size = sizeof(test_distribution) / sizeof(test_distribution[0]);

namespace
{

class TestDB: public cryptonote::BaseTestDB
{
public:
  TestDB(size_t bc_height = test_distribution_size): blockchain_height(bc_height) { m_open = true; }
  virtual uint64_t height() const override { return blockchain_height; }

  std::vector<uint64_t> get_block_cumulative_rct_outputs(const std::vector<uint64_t> &heights) const override
  {
    std::vector<uint64_t> d;
    for (uint64_t h: heights)
    {
      uint64_t c = 0;
      for (uint64_t i = 0; i <= h; ++i)
        c += test_distribution[i];
      d.push_back(c);
    }
    return d;
  }

  std::vector<uint64_t> get_block_weights(uint64_t start_offset, size_t count) const override
  {
    std::vector<uint64_t> weights;
    while (count--) weights.push_back(1);
    return weights;
  }

  uint64_t blockchain_height;
};

}

bool get_output_distribution(uint64_t amount, uint64_t from, uint64_t to, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base)
{
  blockchain_objects_t bc = {};
  struct get_test_options {
    const std::vector<cryptonote::hard_fork> hard_forks{{cryptonote::hf::hf1,0,0,0}};
    const cryptonote::test_options test_options = {
      hard_forks
    };
  } opts;
  cryptonote::Blockchain *blockchain = &bc.m_blockchain;
  bool r = blockchain->init(new TestDB(test_distribution_size), nullptr /*bns_db*/, cryptonote::FAKECHAIN, true, &opts.test_options, 0, NULL);
  return r && blockchain->get_output_distribution(amount, from, to, start_height, distribution, base);
}

crypto::hash get_block_hash(uint64_t height)
{
  crypto::hash hash = crypto::null_hash;
  *((uint64_t*)&hash) = height;
  return hash;
}

TEST(output_distribution, extend)
{
  std::optional<cryptonote::rpc::output_distribution_data> res;

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 28, 29, ::get_block_hash, false, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 2);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({5, 0}));

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 28, 29, ::get_block_hash, true, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 2);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({55, 55}));

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 28, 30, ::get_block_hash, false, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 3);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({5, 0, 2}));

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 28, 30, ::get_block_hash, true, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 3);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({55, 55, 57}));

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 28, 31, ::get_block_hash, false, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 4);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({5, 0, 2, 3}));

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 28, 31, ::get_block_hash, true, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 4);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({55, 55, 57, 60}));
}

TEST(output_distribution, one)
{
  std::optional<cryptonote::rpc::output_distribution_data> res;

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 0, 0, ::get_block_hash, false, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 1);
  ASSERT_EQ(res->distribution.back(), 0);
}

TEST(output_distribution, full_cumulative)
{
  std::optional<cryptonote::rpc::output_distribution_data> res;

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 0, 31, ::get_block_hash, true, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 32);
  ASSERT_EQ(res->distribution.back(), 60);
}

TEST(output_distribution, full_noncumulative)
{
  std::optional<cryptonote::rpc::output_distribution_data> res;

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 0, 31, ::get_block_hash, false, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 32);
  for (size_t i = 0; i < 32; ++i)
    ASSERT_EQ(res->distribution[i], test_distribution[i]);
}

TEST(output_distribution, part_cumulative)
{
  std::optional<cryptonote::rpc::output_distribution_data> res;

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 4, 8, ::get_block_hash, true, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 5);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({0, 1, 6, 7, 11}));
}

TEST(output_distribution, part_noncumulative)
{
  std::optional<cryptonote::rpc::output_distribution_data> res;

  res = cryptonote::rpc::detail::get_output_distribution(::get_output_distribution, 0, 4, 8, ::get_block_hash, false, test_distribution_size);
  ASSERT_TRUE(res != std::nullopt);
  ASSERT_EQ(res->distribution.size(), 5);
  ASSERT_EQ(res->distribution, std::vector<uint64_t>({0, 1, 5, 1, 4}));
}

// ---------------------------------------------------------------------------
// Per-kind cache (native / privacy token) with output indices.
// ---------------------------------------------------------------------------
namespace
{
// A fake chain: per-height output counts for each kind. Global amount-0
// indices are handed out in height order, native first within a block, so the
// two kinds interleave the way they do on a real chain.
struct fake_chain
{
  std::vector<uint64_t> native, token;
  uint8_t fork = 0;          // changes block hashes from `fork_from` up
  uint64_t fork_from = ~0ull;
  size_t fetches = 0;
  uint8_t id = 0;            // distinct per chain: the cache under test is process-wide

  uint64_t height() const { return native.size(); }

  crypto::hash hash(uint64_t h) const
  {
    crypto::hash r = crypto::null_hash;
    *((uint64_t*)&r) = h;
    r.data[31] = 0x5a;                       // never collides with ::get_block_hash
    r.data[30] = h >= fork_from ? fork : 0;
    r.data[29] = id;
    return r;
  }

  bool fetch(bool want_token, uint64_t from, uint64_t to, uint64_t& start_height,
             std::vector<uint64_t>& distribution, uint64_t& base, std::vector<uint64_t>* indices)
  {
    ++fetches;
    if (from >= height() || to >= height())
      return false;
    start_height = from;
    distribution.assign(height() - from, 0);
    if (indices) indices->clear();
    uint64_t global = 0, before = 0;
    for (uint64_t h = 0; h < height(); ++h)
      for (int kind = 0; kind < 2; ++kind)
        for (uint64_t n = 0; n < (kind ? token[h] : native[h]); ++n, ++global)
        {
          if ((kind == 1) != want_token) continue;
          if (h < from) { ++before; continue; }
          if (h > to) continue;
          ++distribution[h - from];
          if (indices) indices->push_back(global);
        }
    distribution[0] += before;
    for (size_t n = 1; n < distribution.size(); ++n)
      distribution[n] += distribution[n - 1];
    base = 0;
    return true;
  }

  std::optional<cryptonote::rpc::output_distribution_data> get(bool want_token, uint64_t from, uint64_t to, bool want_indices = true)
  {
    return cryptonote::rpc::detail::get_output_distribution(
        [this, want_token](uint64_t, uint64_t f, uint64_t t, uint64_t& s, std::vector<uint64_t>& d, uint64_t& b, std::vector<uint64_t>* i) {
          return fetch(want_token, f, t, s, d, b, i);
        },
        0, from, to, [this](uint64_t h) { return hash(h); }, true /*cumulative*/, height(), want_token, want_indices);
  }

  // What an uncached request returns.
  cryptonote::rpc::output_distribution_data expected(bool want_token, uint64_t from, uint64_t to)
  {
    cryptonote::rpc::output_distribution_data e{};
    const size_t saved = fetches;
    fetch(want_token, from, to, e.start_height, e.distribution, e.base, &e.output_indices);
    fetches = saved;
    e.distribution.resize(to - from + 1);
    return e;
  }
};

fake_chain make_chain(uint64_t blocks)
{
  static uint8_t next_id = 0;
  fake_chain c;
  c.id = ++next_id;
  for (uint64_t h = 0; h < blocks; ++h)
  {
    c.native.push_back(1 + h % 3);
    c.token.push_back(h % 4 == 0 ? 2 : 0);
  }
  return c;
}

void expect_same(const std::optional<cryptonote::rpc::output_distribution_data>& got, const cryptonote::rpc::output_distribution_data& want)
{
  ASSERT_TRUE(got != std::nullopt);
  EXPECT_EQ(got->distribution, want.distribution);
  EXPECT_EQ(got->output_indices, want.output_indices);
}
}

TEST(output_distribution, cache_is_per_output_kind_and_keeps_indices)
{
  auto chain = make_chain(40);
  const uint64_t to = chain.height() - 1;

  // First request of each kind hits the chain; the answers differ.
  expect_same(chain.get(false, 0, to), chain.expected(false, 0, to));
  expect_same(chain.get(true, 0, to), chain.expected(true, 0, to));
  EXPECT_EQ(chain.fetches, 2);
  EXPECT_NE(chain.expected(false, 0, to).output_indices, chain.expected(true, 0, to).output_indices);

  // Repeats are served from the cache, each kind getting its own answer.
  for (int i = 0; i < 5; ++i)
  {
    expect_same(chain.get(true, 0, to), chain.expected(true, 0, to));
    expect_same(chain.get(false, 0, to), chain.expected(false, 0, to));
  }
  EXPECT_EQ(chain.fetches, 2);
}

TEST(output_distribution, cache_extends_indices_with_new_blocks)
{
  auto chain = make_chain(40);
  expect_same(chain.get(true, 0, 39), chain.expected(true, 0, 39));
  EXPECT_EQ(chain.fetches, 1);

  for (uint64_t h = 40; h < 48; ++h) { chain.native.push_back(2); chain.token.push_back(h % 2 ? 3 : 0); }
  // Only the new blocks are fetched, and the result equals a full scan.
  expect_same(chain.get(true, 0, 47), chain.expected(true, 0, 47));
  EXPECT_EQ(chain.fetches, 2);
  expect_same(chain.get(true, 0, 47), chain.expected(true, 0, 47));
  EXPECT_EQ(chain.fetches, 2);
}

TEST(output_distribution, cache_follows_a_reorg)
{
  auto chain = make_chain(40);
  expect_same(chain.get(true, 0, 39), chain.expected(true, 0, 39));

  // Replace the top 3 blocks and grow by 2: the tip hash changes, the hash 10
  // below does not, so the cache drops 10 blocks and refetches from there.
  chain.fork = 1;
  chain.fork_from = 37;
  for (uint64_t h = 37; h < 40; ++h) { chain.native[h] = 4; chain.token[h] = 1; }
  chain.native.push_back(1); chain.token.push_back(5);
  chain.native.push_back(1); chain.token.push_back(0);
  expect_same(chain.get(true, 0, 41), chain.expected(true, 0, 41));
  expect_same(chain.get(false, 0, 41), chain.expected(false, 0, 41));

  // A deeper reorg invalidates the cache entirely; the answer is still right.
  chain.fork = 2;
  chain.fork_from = 5;
  for (uint64_t h = 5; h < chain.height(); ++h) chain.token[h] = 1;
  expect_same(chain.get(true, 0, 41), chain.expected(true, 0, 41));
}

TEST(output_distribution, cache_without_indices_is_not_served_to_a_caller_that_needs_them)
{
  auto chain = make_chain(40);
  auto plain = chain.get(false, 0, 39, false /*want_indices*/);
  ASSERT_TRUE(plain != std::nullopt);
  EXPECT_TRUE(plain->output_indices.empty());
  expect_same(chain.get(false, 0, 39, true), chain.expected(false, 0, 39));
}
