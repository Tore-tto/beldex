#include "token_descriptor.h"

#include <algorithm>
#include <cstdint>
#include <limits>

#include <rapidjson/document.h>

#include "common/file.h"
#include "common/hex.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

namespace cryptonote
{
namespace
{
  constexpr bool ascii_digit(unsigned char c) { return c >= '0' && c <= '9'; }
  constexpr bool ascii_alpha(unsigned char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
  constexpr bool ascii_alnum(unsigned char c) { return ascii_digit(c) || ascii_alpha(c); }

  bool token_ticker_ok(std::string_view ticker)
  {
    return !ticker.empty() && ticker.size() <= TOKEN_TICKER_MAX_LENGTH &&
        std::all_of(ticker.begin(), ticker.end(), [](unsigned char c) { return ascii_alnum(c); });
  }

  bool token_full_name_ok(std::string_view full_name)
  {
    return !full_name.empty() && full_name.size() <= TOKEN_FULL_NAME_MAX_LENGTH &&
        std::all_of(full_name.begin(), full_name.end(), [](unsigned char c) {
          return ascii_alnum(c) || c == ' ' || c == '_' || c == '-' || c == '.';
        });
  }

  // Strict UTF-8 (RFC 3629): well-formed sequences only, no overlong forms, no
  // UTF-16 surrogates and nothing above U+10FFFF.
  bool valid_utf8(std::string_view s)
  {
    size_t i = 0;
    while (i < s.size())
    {
      const unsigned char c = static_cast<unsigned char>(s[i]);
      if (c < 0x80) { ++i; continue; }
      size_t len;
      uint32_t cp;
      if      ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
      else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
      else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
      else return false;
      if (s.size() - i < len) return false;
      for (size_t k = 1; k < len; ++k)
      {
        const unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0) != 0x80) return false;
        cp = (cp << 6) | (cc & 0x3F);
      }
      if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000))
        return false;
      if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return false;
      i += len;
    }
    return true;
  }

  bool parse_owner(std::string_view owner, crypto::public_key& out, std::string& error)
  {
    const std::string owner_str{owner};
    address_parse_info owner_info{};
    if (get_account_address_from_str(owner_info, network_type::MAINNET, owner_str) ||
        get_account_address_from_str(owner_info, network_type::TESTNET, owner_str))
    {
      if (owner_info.is_subaddress)
      {
        error = "owner cannot be a subaddress";
        return false;
      }
      out = owner_info.address.m_spend_public_key;
      return true;
    }

    if (!tools::hex_to_type(owner_str, out))
    {
      error = "owner must be a hex-encoded public key or valid address";
      return false;
    }
    return true;
  }
}

bool validate_token_descriptor_for_registration(const token_descriptor_base& descriptor, std::string& error)
{
  if (descriptor.version != TOKEN_DESCRIPTOR_VERSION)
  {
    error = "unsupported token descriptor version";
    return false;
  }
  if (!token_ticker_ok(descriptor.ticker))
  {
    error = "ticker is invalid; expected 1-" + std::to_string(TOKEN_TICKER_MAX_LENGTH) +
            " ASCII alphanumeric characters";
    return false;
  }
  if (!token_full_name_ok(descriptor.full_name))
  {
    error = "full_name is invalid; expected 1-" + std::to_string(TOKEN_FULL_NAME_MAX_LENGTH) +
            " ASCII alphanumeric, space, '_', '-' or '.' characters";
    return false;
  }
  if (descriptor.decimal_point > TOKEN_MAX_DECIMAL_POINT)
  {
    error = "decimal_point must be <= " + std::to_string(TOKEN_MAX_DECIMAL_POINT);
    return false;
  }
  if (descriptor.total_max_supply == 0)
  {
    error = "total_max_supply must be greater than 0";
    return false;
  }
  if (descriptor.current_supply > descriptor.total_max_supply)
  {
    error = "current_supply cannot exceed total_max_supply";
    return false;
  }
  if (descriptor.meta_info.length() > TOKEN_META_INFO_MAX_LENGTH)
  {
    error = "meta_info cannot exceed " + std::to_string(TOKEN_META_INFO_MAX_LENGTH) + " characters";
    return false;
  }

  if (!valid_utf8(descriptor.meta_info))
  {
    error = "meta_info must be valid UTF-8 text";
    return false;
  }
  return true;
}

bool load_token_descriptor_from_json(std::string_view data, token_descriptor_base& descriptor, std::string& error, token_descriptor_json_mode mode)
{
  rapidjson::Document json;
  if (json.Parse(data.data(), data.size()).HasParseError())
  {
    error = "Token specification is not valid JSON";
    return false;
  }
  if (!json.IsObject())
  {
    error = "Token specification root must be a JSON object";
    return false;
  }

  auto assign_string = [&](const char* field, std::string& target, bool required) -> bool {
    const auto it = json.FindMember(field);
    if (it == json.MemberEnd())
    {
      if (required)
        error = std::string{"missing required field: "} + field;
      return !required;
    }
    if (!it->value.IsString())
    {
      error = std::string{field} + " must be a string";
      return false;
    }
    target.assign(it->value.GetString(), it->value.GetStringLength());
    return true;
  };

  auto assign_uint64 = [&](const char* field, uint64_t& target, bool required) -> bool {
    const auto it = json.FindMember(field);
    if (it == json.MemberEnd())
    {
      if (required)
        error = std::string{"missing required field: "} + field;
      return !required;
    }
    if (!it->value.IsUint64())
    {
      error = std::string{field} + " must be an unsigned integer";
      return false;
    }
    target = it->value.GetUint64();
    return true;
  };

  auto assign_uint8 = [&](const char* field, uint8_t& target, bool required) -> bool {
    const auto it = json.FindMember(field);
    if (it == json.MemberEnd())
    {
      if (required)
        error = std::string{"missing required field: "} + field;
      return !required;
    }
    if (!it->value.IsUint())
    {
      error = std::string{field} + " must be an unsigned integer";
      return false;
    }
    const unsigned value = it->value.GetUint();
    if (value > std::numeric_limits<uint8_t>::max())
    {
      error = std::string{field} + " is out of range";
      return false;
    }
    target = static_cast<uint8_t>(value);
    return true;
  };

  const bool registration = mode == token_descriptor_json_mode::registration;
  if (!assign_uint8("version", descriptor.version, false) ||
      !assign_uint64("total_max_supply", descriptor.total_max_supply, registration) ||
      !assign_uint64("current_supply", descriptor.current_supply, false) ||
      !assign_uint8("decimal_point", descriptor.decimal_point, false) ||
      !assign_string("ticker", descriptor.ticker, registration) ||
      !assign_string("full_name", descriptor.full_name, registration) ||
      !assign_string("meta_info", descriptor.meta_info, false))
    return false;

  const auto owner_it = json.FindMember("owner");
  if (owner_it != json.MemberEnd())
  {
    if (!owner_it->value.IsString())
    {
      error = "owner must be a hex-encoded public key or address";
      return false;
    }
    if (!parse_owner({owner_it->value.GetString(), owner_it->value.GetStringLength()}, descriptor.owner, error))
      return false;
  }

  return validate_token_descriptor_for_registration(descriptor, error);
}

bool load_token_descriptor_from_json_file(const fs::path& filename, token_descriptor_base& descriptor, std::string& error, token_descriptor_json_mode mode)
{
  std::string data;
  if (!tools::slurp_file(filename, data))
  {
    error = "Failed to read token specification file";
    return false;
  }
  return load_token_descriptor_from_json(data, descriptor, error, mode);
}
}
