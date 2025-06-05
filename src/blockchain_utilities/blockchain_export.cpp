// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Beldex Project
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

#include "bootstrap_file.h"
#include "blocksdat_file.h"
#include "common/command_line.h"
#include "cryptonote_core/cryptonote_core.h"
#include "blockchain_objects.h"
#include "version.h"
#include "cryptonote_core/uptime_proof.h"
#include <fmt/std.h>

static auto logcat = oxen::log::Cat("bcutil");

namespace po = boost::program_options;

int main(int argc, char* argv[])
{
  TRY_ENTRY();

  epee::string_tools::set_module_name_and_folder(argv[0]);
  uint64_t block_stop = 0;
  bool blocks_dat = false;
  tools::on_startup();
  auto opt_size = command_line::boost_option_sizes();

  po::options_description desc_cmd_only("Command line options", opt_size.first, opt_size.second);
  po::options_description desc_cmd_sett("Command line options and settings options", opt_size.first, opt_size.second);
  const command_line::arg_descriptor<std::string> arg_output_file = {"output-file", "Specify output file", "", true};
  const command_line::arg_descriptor<std::string> arg_log_level  = {"log-level",  "0-4 or categories", ""};
  const command_line::arg_descriptor<uint64_t> arg_block_stop = {"block-stop", "Stop at block number", block_stop};
  const command_line::arg_descriptor<bool> arg_blocks_dat = {"blocksdat", "Output in blocks.dat format", blocks_dat};


  command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
  command_line::add_arg(desc_cmd_sett, arg_output_file);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_devnet_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_block_stop);
  command_line::add_arg(desc_cmd_sett, arg_blocks_dat);

  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Beldex '" << BELDEX_RELEASE_NAME << "' (v" << BELDEX_VERSION_FULL << ")\n\n";
    std::cout << desc_options << std::endl;
    return 1;
  }

  auto m_config_folder = command_line::get_arg(vm, cryptonote::arg_data_dir);
  auto log_file_path = m_config_folder + "beldex-blockchain-export.log";
  oxen::log::Level log_level;
  if(auto level = beldex::logging::parse_level(command_line::get_arg(vm, arg_log_level).c_str())) {
    log_level = *level;
  } else {
      std::cerr << "Incorrect log level: " << command_line::get_arg(vm, arg_log_level).c_str() << std::endl;
      throw std::runtime_error{"Incorrect log level"};
  }
  beldex::logging::init(log_file_path, log_level);
  oxen::log::warning(logcat, "Starting...");
  block_stop = command_line::get_arg(vm, arg_block_stop);

  LOG_PRINT_L0("Starting...");

  bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
  bool opt_devnet = command_line::get_arg(vm, cryptonote::arg_devnet_on);
  if (opt_testnet && opt_devnet)
  {
    std::cerr << "Can't specify more than one of --testnet and --devnet" << std::endl;
    return 1;
  }
  bool opt_blocks_dat = command_line::get_arg(vm, arg_blocks_dat);

  auto config_folder = fs::u8path(command_line::get_arg(vm, cryptonote::arg_data_dir));

  fs::path output_file_path;
  if (command_line::has_arg(vm, arg_output_file))
    output_file_path = fs::u8path(command_line::get_arg(vm, arg_output_file));
  else
    output_file_path = config_folder / "export" / BLOCKCHAIN_RAW;
  oxen::log::warning(logcat, "Export output file: {}", output_file_path.string());

  oxen::log::warning(logcat, "Initializing source blockchain (BlockchainDB)");
  blockchain_objects_t blockchain_objects = {};
  Blockchain *core_storage = &blockchain_objects.m_blockchain;
  BlockchainDB *db = new_db();
  if (db == NULL)
  {
    oxen::log::error(logcat, "Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }
  oxen::log::warning(logcat, "database: LMDB");

  auto filename = config_folder / db->get_db_name();

  oxen::log::warning(logcat, "Loading blockchain from folder {} ...", filename);
  try
  {
    db->open(filename, core_storage->nettype(), DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    oxen::log::warning(logcat, "Error opening database: {}", e.what());
    return 1;
  }
  r = core_storage->init(db, nullptr, opt_testnet ? cryptonote::network_type::TESTNET : opt_devnet ? cryptonote::network_type::DEVNET : cryptonote::network_type::MAINNET);

  if (core_storage->get_blockchain_pruning_seed() && !opt_blocks_dat)
  {
    oxen::log::warning(logcat, "Blockchain is pruned, cannot export");
    return 1;
  }

  CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize source blockchain storage");
  oxen::log::warning(logcat, "Source blockchain storage initialized OK");
  oxen::log::warning(logcat, "Exporting blockchain raw data...");

  if (opt_blocks_dat)
  {
    BlocksdatFile blocksdat;
    r = blocksdat.store_blockchain_raw(core_storage, NULL, output_file_path, block_stop);
  }
  else
  {
    BootstrapFile bootstrap;
    r = bootstrap.store_blockchain_raw(core_storage, NULL, output_file_path, block_stop);
  }
  CHECK_AND_ASSERT_MES(r, 1, "Failed to export blockchain raw data");
  oxen::log::warning(logcat, "Blockchain raw data exported OK");
  return 0;

  CATCH_ENTRY("Export error", 1);
}
