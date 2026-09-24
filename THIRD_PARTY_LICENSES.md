# Third-Party Licenses

Zift links statically against the following open-source libraries.
Release binaries include compiled object code from each. Source for each
pinned version is fetched at build time via `build.zig.zon`; the URLs,
commits and content hashes there (and, for zlib, in the wrapper's own
`build.zig.zon`) are the authoritative pointers to the exact sources
that produced the shipped binary.

## libssh

- Project: <https://www.libssh.org/>
- Version: 0.11.5
- Source: <https://gitlab.com/libssh/libssh-mirror>
- License: LGPL-2.1-or-later, except the files below

LGPL-2.1 obligations are satisfied for statically linked binaries by
publishing the libssh source revision used (pinned in `build.zig.zon`)
and by Zift being itself open source. Operators redistributing the Zift
binary should preserve this notice.

License text: <https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt>

The build also compiles these files from libssh's `src/external/`. The
Ed25519, Curve25519, ChaCha and Poly1305 files are public domain. Two
carry notices that must accompany binaries:

`blowfish.c`:

```
Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

`bcrypt_pbkdf.c`:

```
Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## mbedTLS

- Project: <https://www.trustedfirmware.org/projects/mbed-tls/>
- Version: 3.6.7
- Source: <https://github.com/Mbed-TLS/mbedtls>
- License: Apache-2.0 OR GPL-2.0-or-later, used under Apache-2.0

Required attribution: see the upstream `LICENSE` and `NOTICE` files at
the project source URL above.

License text: <https://www.apache.org/licenses/LICENSE-2.0.txt>

## zlib

- Project: <https://zlib.net/>
- Version: 1.3.2
- Source: <https://github.com/madler/zlib/archive/refs/tags/v1.3.2.tar.gz>,
  fetched and built through the Zig package wrapper
  <https://github.com/allyourcodebase/zlib>, which `build.zig.zon` pins
  by commit
- License: zlib license

The zlib license is permissive and notice-only. The full text is short:

```
This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not
   be misrepresented as being the original software.

3. This notice may not be removed or altered from any source distribution.
```
