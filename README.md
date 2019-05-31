# libnss_aad [![Build Status][travis-badge]][travis-url] [![GPL-3.0-or-later][gpl-badge]][gpl-license] [![Download](https://api.bintray.com/packages/jnchi/aad/libnss-aad/images/download.svg) ](https://bintray.com/jnchi/aad/libnss-aad/_latestVersion)

_Name Service Switch (NSS) Module for performing user lookups against the Azure Active Directory (AAD)._

## Installation

```terminal
make
sudo make install
```

## Configuration

Edit `/etc/nsswitch.conf` to match the following:

```
passwd:         compat aad
group:          compat
shadow:         compat aad
```

Note: The contents of `/etc/nsswitch.conf` differ between distributions.
However, simply ensuring that `aad` is present on the `passwd`, `group`, and `shadow` lines is sufficient.

### Configuration File

Create the file `/etc/libnss-aad.conf` and fill it with:

```mustache
{
  "client": {
    "id": "{{client_id}}",
    "secret": "{{client_secret}}"
  },
  "domain": "{{domain}}",
  "user": {
    "group": "users",
    "shell": "/bin/bash"
  }
}
```

**NOTE: For now, `client.secret` must be URL-encoded.**

## Current behavior

```terminal
id tux
uid=1000(tux) gid=100(users) groups=100(users)

getent passwd tux
tux:x:1000:100::/home/tux:/bin/bash

getent shadow tux
tux:$2a$12$tlMH2KjgjCvd7gV0WVU4g.RxRe2vcXzmJ/WXLUQPRsE3yyjba9YCa:13571:0:99999:7:::
```

## See Also

- https://github.com/outlook/libnss-aad
- https://github.com/donapieppo/libnss-ato

[gpl-badge]: https://img.shields.io/badge/license-GPL-green.svg
[gpl-license]: COPYING
[travis-badge]: https://travis-ci.org/CyberNinjas/libnss_aad.svg?branch=master
[travis-url]: https://travis-ci.org/CyberNinjas/libnss_aad
