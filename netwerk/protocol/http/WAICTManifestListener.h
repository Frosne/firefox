/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef WAICTManifestListener_h__
#define WAICTManifestListener_h__

#include "nsIStreamListener.h"
#include "nsString.h"

namespace mozilla {
namespace net {

class WAICTManifestListener final : public nsIStreamListener {
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSISTREAMLISTENER
  NS_DECL_NSIREQUESTOBSERVER

  WAICTManifestListener();

 private:
  ~WAICTManifestListener();

  nsCString mData;
};

}  // namespace net
}  // namespace mozilla

#endif  // WAICTManifestListener_h__