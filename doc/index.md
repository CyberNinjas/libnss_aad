# libnss-aad

## Compiling

1) Fetch source code:

```terminal
git clone https://github.com/CyberNinjas/libnss_aad

cd libnss_aad
```

2) Compile:

```terminal
make
```

4) Install:

```terminal
sudo make install
```

## Configuration

1) Azure:

- Login to the [Microsoft Azure Portal](portal.azure.com).

- In the sidebar on the left, navigate to "Azure Active Directory", then choose "App registrations (Preview)", then select "New registration".

  - Choose a Name e.g. `Name Service Switch for Azure Active Directory`.

  - For Supported account types select `Accounts in this organizational directory only (Organization Name)`.

- Next click "Register", down at the bottom.

- From the "Overview" page, under "Manage", select "Authentication".

  - For "Supported account types":

    - Select `Accounts in this organizational directory only (Organization Name)`.

- Next, click "Save", back up near the top.

- From the "Overview" page, under "Manage", select "API permissions".

  - Delete any existing permissions (The delegated permission, `Microsoft Graph (1)`, `User.Read` seems to be added by default).

  **NOTE: This module makes use of the `Windows Azure Active Directory` API, not the `Microsoft Graph` API** (pam_aad - [#8](https://github.com/CyberNinjas/pam_aad/issues/8), deprecation notice - [#2](https://github.com/CyberNinjas/libnss_aad/issues/2)).

  - Select "Add a permission", then under "Supported legacy APIs", choose `Azure Active Directory Graph`.

    - Choose "Application permissions".

    - Under "Select permissions", choose `Directory.Read.All`.

2) NSS:

*These instructions assume that the host system is either Debian or one of its derivatives.*

`/etc/libnss-aad.conf`

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
  },
  "debug": true # to optionally enable debugging mode
}
```

**NOTE: For now, `client.secret` must be URL-encoded.**

`/etc/nsswitch.conf`

```
passwd:         compat aad
group:          compat
shadow:         compat aad
```

## Tools

**Syntax Checking and Code Formatting**

```terminal
cp .githooks/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Docker

**Building the container**

```terminal
docker build . -t cyberninjas/libnss_aad
```

**Running the container**

```terminal
docker run -it cyberninjas/libnss_aad /bin/bash
```

**Running the container with local git repository mounted**

```terminal
docker run -v $(pwd):/usr/src/libnss_aad -it cyberninjas/libnss_aad /bin/bash
```

**NOTE: Running `gdb`, or `strace` in the container requires usage of the `--privileged` flag.**

- [Docker run reference](https://docs.docker.com/engine/reference/run)

### getent

    gentent passwd $(whoami)

- [getent](https://en.wikipedia.org/wiki/Getent)

### id

    id $(whoami)

- [id: Print user identity](https://www.gnu.org/software/coreutils/manual/coreutils.html#id-invocation)

## Resources

- [Azure Active Directory Documentation](https://docs.microsoft.com/en-us/azure/active-directory)

- [Service to service calls using client credentials (shared secret or certificate)](https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-oauth2-client-creds-grant-flow)

- [Azure AD v2.0 Protocols (Postman Collection)](https://app.getpostman.com/view-collection/8f5715ec514865a07e6a?referrer=https%3A%2F%2Fapp.getpostman.com%2Frun-collection%2F8f5715ec514865a07e6a)

- [System Databases and Name Service Switch](https://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html)

## See also

- [puppet-aad](https://github.com/Jnchi/puppet-aad)
