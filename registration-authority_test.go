// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package boulder

import (
  "testing"
)

func TestForbiddenIdentifier(t *testing.T) {
  shouldBeAccepted := []string{
    "www.zombo.com",
    "zombo.com",
    "www.163.com", // Technically disallowed (all-numeric label) but actually common.
    "163.com",
    "zom-bo.com",
    "zombo-.com",
    "www.zom-bo.com",
    "www.zombo-.com",
  }
  shouldBeForbidden := []string{
    "127.0.0.1",
    "10.0.0.10",
    "192.168.1.1",
    "123.45.78.12",
    "",
    "0",
    "1",
    "*",
    "**",
    "*.*",
    "zombo*com",
    "*.com",
    "*.zombo.com",
    ".",
    "..",
    "a..",
    "..a",
    ".a.",
    ".....",
    "www.zombo_com.com",
    "\uFEFF", // Byte order mark
    "\uFEFFwww.zombo.com",
    "www.zömbo.com", // No non-ASCII for now.
    "xn--hmr.net", // No punycode for now.
    "xn--.net", // No punycode for now.
    "www.xn--hmr.net",
    "www.zom\u202Ebo.com", // Right-to-Left Override
    "\u202Ewww.zombo.com",
    "www.zom\u200Fbo.com", // Right-to-Left Mark
    "\u200Fwww.zombo.com",
    // 6 * 26 characters = too long for DNS label (max 63).
    "www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com",
    // Labels can't start with dash.
    "www.-ombo.com",
    // Underscores are technically disallowed in DNS. Some DNS
    // implementations accept them but we will be conservative.
    "www.zom_bo.com",
    // All-numeric final label not okay.
    "www.zombo.163",
    "zombocom",
    "a.b.c.d.e.f.g.h.i.j.k", // Too many DNS labels
  }

  for _, identifier := range shouldBeForbidden {
    if ! forbiddenIdentifier(identifier) {
      t.Error("Identifier was not correctly forbidden: ", identifier)
    }
  }

  for _, identifier := range shouldBeAccepted {
    if forbiddenIdentifier(identifier) {
      t.Error("Identifier was incorrectly forbidden: ", identifier)
    }
  }
}
