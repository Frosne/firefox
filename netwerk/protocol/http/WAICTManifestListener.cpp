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

typedef struct {
    uint32_t version;                       // Manifest version
    const char* integrity_policy;           // Null-terminated integrity policy string
    const char* bt_server;                  // Null-terminated BT server string
    const char* metadata;                   // Null-terminated JSON metadata string (or NULL)
    AssetHashPairs asset_pairs;             // Asset hash pairs
    AllowedAnywhereHashes allowed_anywhere; // Allowed-anywhere hashes
} ParsedManifest;

/**
 * Parse a manifest from a C string buffer
 *
 * @param data Pointer to the manifest data
 * @param data_len Length of data in bytes
 * @return Error code (MANIFEST_SUCCESS if parsing succeeds)
 */
ManifestErrorCode manifest_validate(const char* data, uint32_t data_len);

/**
 * Get parsed manifest details
 *
 * @param hashes Valid hashes handle
 * @return Structure containing parsed manifest details (valid while hashes
 * handle is alive, do not free)
*/
ParsedManifest manifest_get_parsed(const ManifestHashesHandle* hashes);


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


ManifestErrorCode manifest_parse_and_get_all(
    const char* data,
    uint32_t data_len,
    ParsedManifest* out_parsed,
    ManifestHashesHandle** out_handle
);



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

    printf("✓ Manifest parsed successfully!\n\n");

    ManifestHashesHandle* handle = nullptr;
    ParsedManifest parsed_manifest;

    ManifestErrorCode result = manifest_parse_and_get_all(
        mData.get(), mData.Length(),
        &parsed_manifest,
        &handle
    );



    if (result != MANIFEST_SUCCESS) {
      // Well, I've just validated it above, so this shouldn't happen...
      // but don't forget to put a nice error message!
    }

    ParsedManifest parsed = manifest_get_parsed(handle);

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
