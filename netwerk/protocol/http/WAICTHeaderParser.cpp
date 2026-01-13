/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WAICTHeaderParser.h"
#include "nsString.h"

namespace mozilla {
namespace net {

WAICTHeaderParser::WAICTHeaderParser(const nsACString& aHeader)
    : mManifestFound(false),
      mMaxAgeSet(false),
      mMaxAge(0),
      mModeSet(false) {
  Parse(aHeader);
}

void WAICTHeaderParser::Parse(const nsACString& aHeader) {
  // Header format: max-age=90, mode="report", manifest=.well-known/waict/manifests/1.json
  
  const char* start = aHeader.BeginReading();
  const char* end = aHeader.EndReading();
  const char* current = start;
  
  while (current < end) {
    // Skip whitespace
    while (current < end && (*current == ' ' || *current == '\t')) {
      current++;
    }
    
    if (current >= end) break;
    
    // Look for directive name
    const char* directiveStart = current;
    while (current < end && *current != '=' && *current != ',') {
      current++;
    }
    
    nsDependentCSubstring directive(directiveStart, current - directiveStart);
    directive.Trim(" \t");
    
    if (current >= end || *current == ',') {
      // No value for this directive, just a flag
      if (*current == ',') current++;
      continue;
    }
    
    // Skip the '='
    current++;
    
    // Skip whitespace after '='
    while (current < end && (*current == ' ' || *current == '\t')) {
      current++;
    }
    
    // Extract value
    const char* valueStart = current;
    bool inQuotes = false;
    
    if (current < end && (*current == '"' || *current == '\'')) {
      inQuotes = true;
      char quoteChar = *current;
      current++;
      valueStart = current;
      
      // Find closing quote
      while (current < end && *current != quoteChar) {
        current++;
      }
    } else {
      // No quotes - read until comma or end
      while (current < end && *current != ',') {
        current++;
      }
    }
    
    nsDependentCSubstring value(valueStart, current - valueStart);
    value.Trim(" \t");
    
    // Parse known directives
    if (directive.EqualsLiteral("manifest")) {
      mManifest = value;
      mManifestFound = true;
    } else if (directive.EqualsLiteral("max-age")) {
      nsresult rv;
      int32_t val = nsCString(value).ToInteger(&rv);
      if (NS_SUCCEEDED(rv) && val >= 0) {
        mMaxAge = static_cast<uint32_t>(val);
        mMaxAgeSet = true;
      }
    } else if (directive.EqualsLiteral("mode")) {
      mMode = value;
      mModeSet = true;
    }
    
    // Move past closing quote if we were in quotes
    if (inQuotes && current < end) {
      current++;
    }
    
    // Move past comma if present
    while (current < end && (*current == ' ' || *current == '\t' || *current == ',')) {
      current++;
    }
  }
}

}  // namespace net
}  // namespace mozilla