/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "mozilla/dom/WAICTUtils.h"
#include "nsCOMPtr.h"
#include "nsString.h"

using namespace mozilla::waict;

// ParseMaxAge Tests

TEST(WAICTHeaderParsing, ParseMaxAge_Valid)
{
  nsCString header = "manifest=\"/test.json\", max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_EQ(maxAge, 90u);
}

TEST(WAICTHeaderParsing, ParseMaxAge_Zero)
{
  nsCString header = "manifest=\"/test.json\", max-age=0, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 999;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_EQ(maxAge, 0u);
}

TEST(WAICTHeaderParsing, ParseMaxAge_LargeValue)
{
  nsCString header =
      "manifest=\"/test.json\", max-age=31536000, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_EQ(maxAge, 31536000u);
}

TEST(WAICTHeaderParsing, ParseMaxAge_Negative)
{
  nsCString header = "manifest=\"/test.json\", max-age=-1, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMaxAge_NegativeLarge)
{
  nsCString header = "manifest=\"/test.json\", max-age=-999999, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMaxAge_Missing)
{
  nsCString header = "manifest=\"/test.json\", mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMaxAge_WrongType_String)
{
  nsCString header =
      "manifest=\"/test.json\", max-age=\"90\", mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

// ParseMode Tests

TEST(WAICTHeaderParsing, ParseMode_Enforce)
{
  nsCString header = "manifest=\"/test.json\", max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_TRUE(enforce);
}

TEST(WAICTHeaderParsing, ParseMode_Audit)
{
  nsCString header = "manifest=\"/test.json\", max-age=90, mode=audit"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = true;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_FALSE(enforce);
}

TEST(WAICTHeaderParsing, ParseMode_Invalid)
{
  nsCString header = "manifest=\"/test.json\", max-age=90, mode=invalid"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMode_Missing)
{
  nsCString header = "manifest=\"/test.json\", max-age=90"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMode_WrongType_Integer)
{
  nsCString header = "manifest=\"/test.json\", max-age=90, mode=1"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMode_WrongType_String)
{
  nsCString header =
      "manifest=\"/test.json\", max-age=90, mode=\"enforce\""_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMode_CaseSensitive_ENFORCE)
{
  nsCString header = "manifest=\"/test.json\", max-age=90, mode=ENFORCE"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseMode_CaseSensitive_Enforce)
{
  nsCString header = "manifest=\"/test.json\", max-age=90, mode=Enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

// ParseManifest Tests

TEST(WAICTHeaderParsing, ParseManifest_Valid)
{
  nsCString header =
      "manifest=\"/manifest.json\", max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_STREQ(manifest.get(), "/manifest.json");
}

TEST(WAICTHeaderParsing, ParseManifest_ValidURL)
{
  nsCString header =
      "manifest=\"https://example.com/manifest.json\", max-age=90, "
      "mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_STREQ(manifest.get(), "https://example.com/manifest.json");
}

TEST(WAICTHeaderParsing, ParseManifest_Empty)
{
  nsCString header = "manifest=\"\", max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseManifest_Missing)
{
  nsCString header = "max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseManifest_WrongType_Integer)
{
  nsCString header = "manifest=123, max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, ParseManifest_WrongType_Token)
{
  nsCString header = "manifest=test, max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

// Combined header parsing tests

TEST(WAICTHeaderParsing, CompleteHeader_AllValid)
{
  nsCString header = "manifest=\"/manifest.json\", max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_STREQ(manifest.get(), "/manifest.json");
  EXPECT_EQ(maxAge, 90u);
  EXPECT_TRUE(enforce);
}

TEST(WAICTHeaderParsing, CompleteHeader_AuditMode)
{
  nsCString header = "manifest=\"/manifest.json\", max-age=3600, mode=audit"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = true;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_SUCCEEDED(rv));
  EXPECT_STREQ(manifest.get(), "/manifest.json");
  EXPECT_EQ(maxAge, 3600u);
  EXPECT_FALSE(enforce);
}

TEST(WAICTHeaderParsing, CompleteHeader_OneInvalid_MaxAge)
{
  nsCString header = "manifest=\"/manifest.json\", max-age=-1, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, CompleteHeader_OneInvalid_Mode)
{
  nsCString header = "manifest=\"/manifest.json\", max-age=90, mode=invalid"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}

TEST(WAICTHeaderParsing, CompleteHeader_MissingManifest)
{
  nsCString header = "max-age=90, mode=enforce"_ns;
  nsAutoCString manifest;
  uint64_t maxAge = 0;
  bool enforce = false;
  nsresult rv = ParseWAICTHeader(header, manifest, &maxAge, &enforce);

  EXPECT_TRUE(NS_FAILED(rv));
}
