# Third-Party Licenses

Zift links statically against the following open-source libraries.
Release binaries include compiled object code from each. Source for each
pinned version is fetched at build time via `build.zig.zon`; the URLs and
commit hashes there are the authoritative pointers to the exact sources
that produced the shipped binary.

## libssh

- Project: <https://www.libssh.org/>
- Version: 0.11.3
- Source: <https://gitlab.com/libssh/libssh-mirror>
- License: LGPL-2.1-or-later

LGPL-2.1 obligations are satisfied for statically linked binaries by
publishing the libssh source revision used (pinned in `build.zig.zon`)
and by Zift being itself open source. Operators redistributing the Zift
binary should preserve this notice.

License text: <https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt>

## mbedTLS

- Project: <https://www.trustedfirmware.org/projects/mbed-tls/>
- Version: 3.6.4
- Source: <https://github.com/Mbed-TLS/mbedtls>
- License: Apache-2.0

Required attribution: see the upstream `LICENSE` and `NOTICE` files at
the project source URL above.

License text: <https://www.apache.org/licenses/LICENSE-2.0.txt>

## zlib

- Project: <https://zlib.net/>
- Version: 1.3.2
- Source: <https://github.com/madler/zlib>
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
