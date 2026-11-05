//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/net/PublicRsaKeySharedMain.h"

#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"

namespace td {

std::shared_ptr<PublicRsaKeySharedMain> PublicRsaKeySharedMain::create(bool is_test) {
  auto add_pem = [](vector<RsaKey> &keys, CSlice pem) {
    auto rsa = mtproto::RSA::from_pem_public_key(pem).move_as_ok();
    auto fingerprint = rsa.get_fingerprint();
    keys.push_back(RsaKey{std::move(rsa), fingerprint});
  };

  if (is_test) {
    static auto test_public_rsa_key = [&] {
      vector<RsaKey> keys;
      add_pem(keys,
              "-----BEGIN RSA PUBLIC KEY-----\n"
              "MIIBCgKCAQEA107kEe7nCQZ0NOTu1F68yTZtKpCAAVd/ioG7FON2stY3L5ZWG4fz\n"
              "0+nxESxv136HpeEm3iTeBwIOgC6Isn+/PoGQY5u7+vijOVb2intE+wSNCJgFbiR3\n"
              "hXTqLABGJBf5OTD3H5eF7FN/VO/rWa0VvSeW3yhYFRVCjqXXy3RGg5vJlVV7uzRx\n"
              "VYj4y+6rzEmB6Au0/IEc8rBj3OfnfoJdn6zS13ifpsCmIo+OR9ZrV4R8wrN0i7G8\n"
              "isQ0z3FAGXf864HMGodtrwABlrTmI3H4yHKmhkXmM7tF6HtX97LmNCnX4j6v6FID\n"
              "v+v9PyqLJt5j30a+MiM+tWXRveI0q2P6fwIDAQAB\n"
              "-----END RSA PUBLIC KEY-----");
      return std::make_shared<PublicRsaKeySharedMain>(std::move(keys));
    }();
    return test_public_rsa_key;
  } else {
    static auto main_public_rsa_key = [&] {
      vector<RsaKey> keys;
      add_pem(keys,
              "-----BEGIN RSA PUBLIC KEY-----\n"
              "MIIBCgKCAQEA107kEe7nCQZ0NOTu1F68yTZtKpCAAVd/ioG7FON2stY3L5ZWG4fz\n"
              "0+nxESxv136HpeEm3iTeBwIOgC6Isn+/PoGQY5u7+vijOVb2intE+wSNCJgFbiR3\n"
              "hXTqLABGJBf5OTD3H5eF7FN/VO/rWa0VvSeW3yhYFRVCjqXXy3RGg5vJlVV7uzRx\n"
              "VYj4y+6rzEmB6Au0/IEc8rBj3OfnfoJdn6zS13ifpsCmIo+OR9ZrV4R8wrN0i7G8\n"
              "isQ0z3FAGXf864HMGodtrwABlrTmI3H4yHKmhkXmM7tF6HtX97LmNCnX4j6v6FID\n"
              "v+v9PyqLJt5j30a+MiM+tWXRveI0q2P6fwIDAQAB\n"
              "-----END RSA PUBLIC KEY-----");
      return std::make_shared<PublicRsaKeySharedMain>(std::move(keys));
    }();
    return main_public_rsa_key;
  }
}

Result<mtproto::PublicRsaKeyInterface::RsaKey> PublicRsaKeySharedMain::get_rsa_key(const vector<int64> &fingerprints) {
  for (auto fingerprint : fingerprints) {
    for (const auto &key : keys_) {
      if (key.fingerprint == fingerprint) {
        return RsaKey{key.rsa.clone(), fingerprint};
      }
    }
  }
  return Status::Error(PSLICE() << "Unknown Main fingerprints " << fingerprints);
}

void PublicRsaKeySharedMain::drop_keys() {
  // nothing to do
}

}  // namespace td
