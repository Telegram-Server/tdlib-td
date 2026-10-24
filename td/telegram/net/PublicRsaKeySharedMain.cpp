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
              "MIIBCgKCAQEAxF//0M0+/5PzgdNagTX+J+dJgr75ZCTuiG8i4x7YwmJF+jiOGCjm\n"
              "7X7BLCaMc1+hOZYDL3+Gvle/AKykW1qouaCJMVx/H+2l8LFXLelZ2PLawTb8A7Bl\n"
              "TqWzL3db5BugMNWziL9TuhR8In1bwKY07QVpR9in5zjAsAGLBk+mGt0DnVyMf1Xo\n"
              "p2lLCFNmm0F4ykcAeaLCCIPbGWddliLY8xEEhI4GO2l1U3kZMwIOdOnAGJFtgUAo\n"
              "Te+FHR6F1s9adCVZB1teL/hf9R+WmekJwygVz0MYEH7y6U49T45+/W7OF6X6g0W0\n"
              "j1uSSrsY4qN7twxbTad9zdGZ7ys+9v+PuQIDAQAB\n"
              "-----END RSA PUBLIC KEY-----");
      return std::make_shared<PublicRsaKeySharedMain>(std::move(keys));
    }();
    return test_public_rsa_key;
  } else {
    static auto main_public_rsa_key = [&] {
      vector<RsaKey> keys;
      add_pem(keys,
              "-----BEGIN RSA PUBLIC KEY-----\n"
              "MIIBCgKCAQEAxF//0M0+/5PzgdNagTX+J+dJgr75ZCTuiG8i4x7YwmJF+jiOGCjm\n"
              "7X7BLCaMc1+hOZYDL3+Gvle/AKykW1qouaCJMVx/H+2l8LFXLelZ2PLawTb8A7Bl\n"
              "TqWzL3db5BugMNWziL9TuhR8In1bwKY07QVpR9in5zjAsAGLBk+mGt0DnVyMf1Xo\n"
              "p2lLCFNmm0F4ykcAeaLCCIPbGWddliLY8xEEhI4GO2l1U3kZMwIOdOnAGJFtgUAo\n"
              "Te+FHR6F1s9adCVZB1teL/hf9R+WmekJwygVz0MYEH7y6U49T45+/W7OF6X6g0W0\n"
              "j1uSSrsY4qN7twxbTad9zdGZ7ys+9v+PuQIDAQAB\n"
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
