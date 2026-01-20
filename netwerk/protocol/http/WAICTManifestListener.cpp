/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WAICTManifestListener.h"
#include "nsIInputStream.h"
#include "nsStreamUtils.h"
#include <stdio.h>

#include "waict_manifest_parser.h"

namespace mozilla {
namespace net {

WAICTManifestListener::WAICTManifestListener() {}

WAICTManifestListener::~WAICTManifestListener() {}

NS_IMPL_ISUPPORTS(WAICTManifestListener, nsIStreamListener, nsIRequestObserver)

NS_IMETHODIMP
WAICTManifestListener::OnStartRequest(nsIRequest* aRequest) { return NS_OK; }

NS_IMETHODIMP
WAICTManifestListener::OnDataAvailable(nsIRequest* aRequest,
                                       nsIInputStream* aInputStream,
                                       uint64_t aOffset, uint32_t aCount) {
  nsAutoCString buffer;
  nsresult rv = NS_ConsumeStream(aInputStream, aCount, buffer);
  if (NS_SUCCEEDED(rv)) {
    mData.Append(buffer);
    printf("=== Received %u bytes of manifest data\n", aCount);
  }
  return rv;
}

NS_IMETHODIMP
WAICTManifestListener::OnStopRequest(nsIRequest* aRequest, nsresult aStatus) {
  if (NS_SUCCEEDED(aStatus)) {
    printf("=== WAICT Manifest received (%u bytes):\n%s\n",
           (uint32_t)mData.Length(), mData.get());

    ManifestErrorCode resultManifestValidate =
        manifest_validate(mData.get(), mData.Length());

    if (resultManifestValidate == ManifestErrorCode::Success) {
      printf("=== Manifest validation succeeded\n");
    } else {
      printf("=== Manifest validation failed with error code: %d\n",
             resultManifestValidate);
      return NS_ERROR_FAILURE;
    }

    printf("✓ Manifest parsed successfully!\n\n");

    ManifestHashesHandle* handle = nullptr;
    ParsedManifest parsed;

    ManifestErrorCode result = manifest_parse_and_get_all(
        mData.get(), mData.Length(),
        &parsed,
        &handle
    );

    if (result != ManifestErrorCode::Success) {
      return NS_ERROR_FAILURE;
    }

    printf("=== Manifest Fields ===\n");
    printf("Version: %u\n", parsed.version);
    printf("Integrity Policy: %s\n", parsed.integrity_policy);
    printf("BT Server: %s\n", parsed.bt_server);
    if (parsed.metadata) {
        printf("Metadata: %s\n", parsed.metadata);
    }
    printf("\n");
    
    // Asset hashes
    printf("Asset hashes (%u):\n", parsed.asset_pairs.count);
    for (uint32_t i = 0; i < parsed.asset_pairs.count; i++) {
        const AssetHashPair& pair = parsed.asset_pairs.pairs[i];
        printf("  \"%s\" -> \"%s\"\n", pair.path, pair.hash);
    }
    printf("\n");
    
    // Allowed-anywhere hashes - Now even sorted!
    if (parsed.allowed_anywhere.count > 0) {
        printf("Allowed-anywhere hashes (%u):\n", parsed.allowed_anywhere.count);
        for (uint32_t i = 0; i < parsed.allowed_anywhere.count; i++) {
            printf("  \"\" -> \"%s\"\n", parsed.allowed_anywhere.hashes[i]);
        }
        printf("\n");
    }

    // Yes, and this please:
    // manifest_hashes_free(handle);
    return NS_OK;
  }
  return NS_OK;
}
}  // namespace net
}  // namespace mozilla
