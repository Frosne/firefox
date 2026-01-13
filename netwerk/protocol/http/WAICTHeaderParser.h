/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef WAICTHeaderParser_h__
#define WAICTHeaderParser_h__

// AW: same as for cachecontrol parser
#include "nsString.h"

namespace mozilla {
namespace net {

class WAICTHeaderParser {
 public:
  explicit WAICTHeaderParser(const nsACString& aHeader);

  bool ManifestFound() const { return mManifestFound; }
  const nsCString& Manifest() const { return mManifest; }
  
  uint32_t MaxAge() const { return mMaxAge; }
  bool MaxAgeSet() const { return mMaxAgeSet; }
  
  const nsCString& Mode() const { return mMode; }
  bool ModeSet() const { return mModeSet; }

 private:
  void Parse(const nsACString& aHeader);
  
  bool mManifestFound;
  nsCString mManifest;
  
  bool mMaxAgeSet;
  uint32_t mMaxAge;
  
  bool mModeSet;
  nsCString mMode;
};

}  // namespace net
}  // namespace mozilla

#endif  // WAICTHeaderParser_h__