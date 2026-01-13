/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "WAICTHeaderParser.h"

using namespace mozilla::net;

// AI generated
TEST(TestWAICTHeaderParser, ManifestOnly)
{
  WAICTHeaderParser waict("manifest=.well-known/waict/manifest.json"_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), ".well-known/waict/manifest.json");
  ASSERT_FALSE(waict.MaxAgeSet());
  ASSERT_FALSE(waict.ModeSet());
}

TEST(TestWAICTHeaderParser, FullHeader)
{
  WAICTHeaderParser waict("max-age=90, mode=\"report\", preload=?0, reporting-endpoint=foo-reports, manifest=.well-known/waict/manifests/1.json"_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), ".well-known/waict/manifests/1.json");
  ASSERT_TRUE(waict.MaxAgeSet());
  ASSERT_EQ(waict.MaxAge(), 90u);
  ASSERT_TRUE(waict.ModeSet());
  ASSERT_STREQ(waict.Mode().get(), "report");
}

TEST(TestWAICTHeaderParser, QuotedManifest)
{
  WAICTHeaderParser waict("manifest=\"/path/to/manifest.json\""_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), "/path/to/manifest.json");
}

TEST(TestWAICTHeaderParser, SingleQuotedManifest)
{
  WAICTHeaderParser waict("manifest='/path/to/manifest.json'"_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), "/path/to/manifest.json");
}

TEST(TestWAICTHeaderParser, WithWhitespace)
{
  WAICTHeaderParser waict("  max-age = 3600 ,  manifest = path/file.json  "_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), "path/file.json");
  ASSERT_TRUE(waict.MaxAgeSet());
  ASSERT_EQ(waict.MaxAge(), 3600u);
}

TEST(TestWAICTHeaderParser, NoManifest)
{
  WAICTHeaderParser waict("max-age=90, mode=\"enforce\""_ns);
  
  ASSERT_FALSE(waict.ManifestFound());
  ASSERT_TRUE(waict.MaxAgeSet());
  ASSERT_EQ(waict.MaxAge(), 90u);
  ASSERT_TRUE(waict.ModeSet());
  ASSERT_STREQ(waict.Mode().get(), "enforce");
}

TEST(TestWAICTHeaderParser, EmptyHeader)
{
  WAICTHeaderParser waict(""_ns);
  
  ASSERT_FALSE(waict.ManifestFound());
  ASSERT_FALSE(waict.MaxAgeSet());
  ASSERT_FALSE(waict.ModeSet());
}

TEST(TestWAICTHeaderParser, ManifestAtEnd)
{
  WAICTHeaderParser waict("mode=\"report\", max-age=120, manifest=file.json"_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), "file.json");
}

TEST(TestWAICTHeaderParser, ManifestAtBeginning)
{
  WAICTHeaderParser waict("manifest=first.json, mode=\"report\", max-age=120"_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), "first.json");
}

TEST(TestWAICTHeaderParser, ComplexPath)
{
  WAICTHeaderParser waict("manifest=/.well-known/waict/v1/manifests/app-123.json"_ns);
  
  ASSERT_TRUE(waict.ManifestFound());
  ASSERT_STREQ(waict.Manifest().get(), "/.well-known/waict/v1/manifests/app-123.json");
}

TEST(TestWAICTHeaderParser, ModeEnforce)
{
  WAICTHeaderParser waict("mode=\"enforce\", manifest=file.json"_ns);
  
  ASSERT_TRUE(waict.ModeSet());
  ASSERT_STREQ(waict.Mode().get(), "enforce");
}

TEST(TestWAICTHeaderParser, LargeMaxAge)
{
  WAICTHeaderParser waict("max-age=31536000, manifest=file.json"_ns);
  
  ASSERT_TRUE(waict.MaxAgeSet());
  ASSERT_EQ(waict.MaxAge(), 31536000u);
}