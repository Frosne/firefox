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

extern "C" {

typedef struct ManifestHashesHandle ManifestHashesHandle;

typedef enum {
  MANIFEST_SUCCESS = 0,
  MANIFEST_INVALID_SYNTAX = 1,
  MANIFEST_INVALID_STRUCTURE = 2,
  MANIFEST_UNSUPPORTED_VERSION = 3,
  MANIFEST_NULL_POINTER = 4,
  MANIFEST_INVALID_ENCODING = 5,
} ManifestErrorCode;

// Single asset hash pair (path + hash)
typedef struct {
  const char* path;  // Null-terminated asset path
  const char* hash;  // Null-terminated hash for this asset
} AssetHashPair;

// Array of asset hash pairs
typedef struct {
  uint32_t count;              // Number of pairs
  const AssetHashPair* pairs;  // Array of AssetHashPair structs
} AssetHashPairs;

// Array of allowed-anywhere hashes
typedef struct {
  uint32_t count;             // Number of hashes
  const char* const* hashes;  // Array of hashes (null-terminated strings)
} AllowedAnywhereHashes;

/**
 * Parse a manifest from a C string buffer
 *
 * @param data Pointer to the manifest data
 * @param data_len Length of data in bytes
 * @return Error code (MANIFEST_SUCCESS if parsing succeeds)
 */
ManifestErrorCode manifest_validate(const char* data, uint32_t data_len);

/**
 * Parse a manifest and extract hashes
 *
 * @param data Pointer to the manifest data
 * @param data_len Length of data in bytes
 * @param out_hashes Output pointer to receive the hashes handle (must be freed
 * with manifest_hashes_free)
 * @return Error code (MANIFEST_SUCCESS if parsing succeeds)
 */
ManifestErrorCode manifest_parse_and_get_hashes(
    const char* data, uint32_t data_len, ManifestHashesHandle** out_hashes);

/**
 * Get asset hash pairs
 * Returns an array of structs, each containing a path and its hash
 *
 * @param hashes Valid hashes handle
 * @return Structure containing count and array (valid while hashes handle is
 * alive, do not free)
 */
AssetHashPairs manifest_hashes_get_asset_pairs(
    const ManifestHashesHandle* hashes);

/**
 * Get allowed-anywhere hashes
 * Returns array of hashes that can be used for any resource
 *
 * @param hashes Valid hashes handle
 * @return Structure containing count and array (valid while hashes handle is
 * alive, do not free)
 */
AllowedAnywhereHashes manifest_hashes_get_allowed_anywhere(
    const ManifestHashesHandle* hashes);

/**
 * Free a manifest hashes handle
 *
 * @param hashes Hashes handle to free (can be null)
 */
void manifest_hashes_free(ManifestHashesHandle* hashes);

}  // extern "C"

NS_IMETHODIMP
WAICTManifestListener::OnStopRequest(nsIRequest* aRequest, nsresult aStatus) {
  if (NS_SUCCEEDED(aStatus)) {
    printf("=== WAICT Manifest received (%u bytes):\n%s\n",
           (uint32_t)mData.Length(), mData.get());

    // AW: We don't really need to validate it here, the function to get the
    // hashes would do that anyway.

    ManifestErrorCode resultManifestValidate =
        manifest_validate(mData.get(), mData.Length());

    if (resultManifestValidate == MANIFEST_SUCCESS) {
      printf("=== Manifest validation succeeded\n");
    } else {
      printf("=== Manifest validation failed with error code: %d\n",
             resultManifestValidate);
    }
    // Parse the manifest and get hashes
    ManifestHashesHandle* handle = nullptr;
    ManifestErrorCode result =
        manifest_parse_and_get_hashes(mData.get(), mData.Length(), &handle);

    if (result != MANIFEST_SUCCESS) {
      return NS_ERROR_FAILURE;
    }

    printf("✓ Manifest parsed successfully!\n\n");

    // Get asset hash pairs
    AssetHashPairs asset_pairs = manifest_hashes_get_asset_pairs(handle);

    printf("Asset hashes (%u):\n", asset_pairs.count);
    for (uint32_t i = 0; i < asset_pairs.count; i++) {
      const AssetHashPair& pair = asset_pairs.pairs[i];
      printf("  \"%s\" -> \"%s\"\n", pair.path, pair.hash);
    }
    printf("\n");

    // Get allowed-anywhere hashes
    AllowedAnywhereHashes allowed =
        manifest_hashes_get_allowed_anywhere(handle);

    if (allowed.count > 0) {
      printf("Allowed-anywhere hashes (%u):\n", allowed.count);
      for (uint32_t i = 0; i < allowed.count; i++) {
        printf("  \"\" -> \"%s\"\n", allowed.hashes[i]);
      }
      printf("\n");
    }

    // Clean up
    manifest_hashes_free(handle);
    return NS_OK;
  }
  return NS_OK;
}
}  // namespace net
}  // namespace mozilla
