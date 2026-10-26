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
              "MIIBCgKCAQEAtPlt6U0dU1qqkVJx7m5gBKr5Iy1vUB7+IsX1qiM0uwGVBNUuMEWW\n"
              "DyMaEWxFWWBGne10mgZyIQ6Q3nf/tKP81LYJvvIsDcxrD3U8JLTJJ5UJGL2ACF0J\n"
              "h/DQ9zLJBf/qlxurKDiPpO3dszYhYsYH5V+17Xqm7+mzdloCViHfDIbL3wZ3n18R\n"
              "JtmuWWHlGrMEc9hnGUgiuu3bPMCNHY4Dxau7t2bWIg9YIS//+i5+rhbtJnP0RpBy\n"
              "vzlESMCcXdqND3l4VPXhGKBl5RYoJuht/901xnnGOf6lrsHUsRZbtd85+iN5UGYZ\n"
              "Jp6IPTpi4fUiCQGGM5qBga0rd5Tt/krUswIDAQAB\n"
              "-----END RSA PUBLIC KEY-----");
      return std::make_shared<PublicRsaKeySharedMain>(std::move(keys));
    }();
    return test_public_rsa_key;
  } else {
    static auto main_public_rsa_key = [&] {
      vector<RsaKey> keys;
      add_pem(keys,
              "-----BEGIN RSA PUBLIC KEY-----\n"
              "MIIBCgKCAQEAtPlt6U0dU1qqkVJx7m5gBKr5Iy1vUB7+IsX1qiM0uwGVBNUuMEWW\n"
              "DyMaEWxFWWBGne10mgZyIQ6Q3nf/tKP81LYJvvIsDcxrD3U8JLTJJ5UJGL2ACF0J\n"
              "h/DQ9zLJBf/qlxurKDiPpO3dszYhYsYH5V+17Xqm7+mzdloCViHfDIbL3wZ3n18R\n"
              "JtmuWWHlGrMEc9hnGUgiuu3bPMCNHY4Dxau7t2bWIg9YIS//+i5+rhbtJnP0RpBy\n"
              "vzlESMCcXdqND3l4VPXhGKBl5RYoJuht/901xnnGOf6lrsHUsRZbtd85+iN5UGYZ\n"
              "Jp6IPTpi4fUiCQGGM5qBga0rd5Tt/krUswIDAQAB\n"
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
