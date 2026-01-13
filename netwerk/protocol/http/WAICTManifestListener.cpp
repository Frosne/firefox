/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WAICTManifestListener.h"
#include "nsIInputStream.h"
#include "nsStreamUtils.h"
#include <stdio.h>

namespace mozilla {
namespace net {

WAICTManifestListener::WAICTManifestListener() {
  printf("=== WAICTManifestListener created\n");
}

WAICTManifestListener::~WAICTManifestListener() {
  printf("=== WAICTManifestListener destroyed\n");
}

NS_IMPL_ISUPPORTS(WAICTManifestListener, nsIStreamListener, nsIRequestObserver)

NS_IMETHODIMP
WAICTManifestListener::OnStartRequest(nsIRequest* aRequest) {
  printf("=== WAICT Manifest download started\n");
  return NS_OK;
}

NS_IMETHODIMP
WAICTManifestListener::OnDataAvailable(nsIRequest* aRequest,
                                       nsIInputStream* aInputStream,
                                       uint64_t aOffset,
                                       uint32_t aCount) {
  nsAutoCString buffer;
  nsresult rv = NS_ConsumeStream(aInputStream, aCount, buffer);
  if (NS_SUCCEEDED(rv)) {
    mData.Append(buffer);
    printf("=== Received %u bytes of manifest data\n", aCount);
  }
  return rv;
}

extern "C" {
typedef enum {
    MANIFEST_SUCCESS = 0,
    MANIFEST_INVALID_SYNTAX = 1,
    MANIFEST_INVALID_STRUCTURE = 2,
    MANIFEST_UNSUPPORTED_VERSION = 3,
    MANIFEST_NULL_POINTER = 4,
    MANIFEST_INVALID_ENCODING = 5,
} ManifestErrorCode;

ManifestErrorCode manifest_validate(const char* data, uint32_t data_len);


}  // extern "C"

NS_IMETHODIMP
WAICTManifestListener::OnStopRequest(nsIRequest* aRequest, nsresult aStatus) {
  if (NS_SUCCEEDED(aStatus)) {
    printf("=== WAICT Manifest received (%u bytes):\n%s\n",
           (uint32_t)mData.Length(),
           mData.get());

    // AW: We don't really need to validate it here, the function to get the hashes
    // would do that anyway.

    // Validate the manifest
    ManifestErrorCode result = manifest_validate(mData.get(), mData.Length());

    if (result == MANIFEST_SUCCESS) {
      printf("=== Manifest validation succeeded\n");
    } else {
      printf("=== Manifest validation failed with error code: %d\n", result);
    }

    // // Call Rust FFI to parse and extract hashes
    // auto* result = waict_parse_manifest(mData.get());

    // if (result->error_message != nullptr) {
    //   printf("=== Failed to parse manifest: %s\n", result->error_message);
    // } else {
    //   printf("=== Successfully parsed manifest\n");
    //   printf("=== Allowed anywhere hashes: %zu\n", result->allowed_anywhere.count);

    //   for (size_t i = 0; i < result->allowed_anywhere.count; i++) {
    //     printf("===   - %s\n", result->allowed_anywhere.hashes[i]);
    //   }

    //   printf("=== Asset hashes: %zu assets\n", result->assets_count);
    //   for (size_t i = 0; i < result->assets_count; i++) {
    //     printf("===   %s:\n", result->assets[i].path);
    //     for (size_t j = 0; j < result->assets[i].hashes.count; j++) {
    //       printf("===     - %s\n", result->assets[i].hashes.hashes[j]);
    //     }
    //   }
    // }

  //   // Clean up
  //   waict_free_manifest_hashes(result);

  // } else {
  //   printf("=== WAICT Manifest fetch failed: %x\n", (uint32_t)aStatus);
  }
  return NS_OK;
}

}  // namespace net
}  // namespace mozilla