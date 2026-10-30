# Recovered EU `260128` Dropbear activation and authentication review

Status: **inert in the recovered filesystem. Package/configuration remnants and
a root authorized public key exist, but the server executable, socket unit,
host-key service/key, and enable links do not. No SSH listener or usable login
path is established.**

Target: recovered European Gen5W Linux
`NE_E.EUR.S5W_L.001.001.260128`. This is a static filesystem review; the owner's
installed firmware is unknown. No service, listener, login, credential, target
binary, or network was used.

## Exact artifacts

The recovered RPM inventory includes `dropbear-2020.81-r8mango2`, but package
metadata is not proof that its executable survives in the product image.

| Artifact | SHA-256 / result |
|---|---|
| `dropbear@.service` | `dbb3f36f9b6ca7aca1b44f577d311450e472cade6847a37e195c22ce6794ca59` |
| `/etc/default/dropbear` | `b357e4ee48b20f990e088ac14eb6443a5a03122025bf946587cf3b9aa3008ca8` |
| `dropbear_publickey_installer.sh` | `04440e440073f7768347cc931b4573d753cda7073277241747b421cf6d2bd5d9` |
| `/etc/dropbear/authorized_keys` | `554cc38c6f4caf5dba066c618669a98f330ec420207976fd906d355b55185980` |
| Public-key fingerprint | `SHA256:dUfV2bm2NcfJODhShzwqpAsz5sHtS1REtNp1VhNp2Mg`, comment `rsa-key-20181102` |
| `/usr/lib/opkg/alternatives/ssh` | points to absent `/usr/sbin/dropbearmulti`; SHA-256 `a78bb579308926a8024102c1be841cb1f7cf1dc80c6f46bb54110b136ee67101` |

## Intended unit and authentication semantics

The template unit would run:

```text
/usr/sbin/dropbear -i -s -r /var/dropbear/dropbear_rsa_host_key ...
```

It uses `StandardInput=socket`, so each template instance expects a connection
from a socket unit. `-i` selects inetd/socket mode and `-s` disables password
login. The default configuration comments out `DROPBEAR_EXTRA_ARGS="-w"`, so
the static command does not disable root login.

Before launch, `dropbear_publickey_installer.sh` copies the shipped key to
`/home/root/.ssh/authorized_keys`; if a different file already exists, it is
replaced. If every missing runtime component were restored, this design would
provide a root public-key authentication route to a party holding the matching
private key. The recovered artifact is only the public key. It does not reveal
or substitute for that private key.

The unit requires `/tmp/secure_console_disable`. Recovered `esinit` creates that
marker by default and removes it only when the MICOM `secure_console` parameter
is `1`. Thus the marker is not the primary blocker in the default
no-secure-console branch.

## Why the recovered route is inert

The following objects needed for the intended complete chain are absent:

- `/usr/sbin/dropbear`;
- `/usr/sbin/dropbearmulti`;
- `dropbear.socket`;
- `dropbearkey.service` even though the template has a soft `Wants=` dependency;
- `/var/dropbear/dropbear_rsa_host_key`.

No Dropbear service/socket enable symlink was found. The alternatives record is
plain metadata pointing to the missing multi-call executable. The template
cannot itself listen: it is socket-fed and no recovered socket unit provides a
port or instantiated connection.

No explicit Dropbear SMACK rule or unit process-label assignment was found.
Because no executable or process exists, assigning it a runtime uid/SMACK
boundary would be speculative. The unit has no `User=`, so it would default to
uid 0 only if a complete activation chain and executable were restored.

## Security conclusion

The static public key and permissive intended root-public-key setup are latent
trust/configuration material worth removing from production images. They are
not a backdoor or remote entry path by themselves:

- no server executable is present;
- no socket listener is defined or enabled;
- no host key exists;
- no candidate private-key material was identified under the recovered
  `mango-rootfs` by filename patterns `*.pem`, `*private*key*`, `id_rsa`, or
  `id_ed25519`, or by PEM markers `BEGIN [RSA|OPENSSH|EC] PRIVATE KEY`; the
  shipped public key was the only ordinary `ssh-rsa` occurrence. With no
  candidate, no cryptographic public/private comparison was possible;
- no accepted authentication or network reachability was observed.

Consequently, version-derived Dropbear CVEs and SSH banner assumptions do not
apply to this recovered image unless an installed owner image independently
contains and activates a server binary.

## Remediation and bench validation

Remove the stale package record, template, installer, alternatives metadata,
and static public key if SSH is not a supported production feature. If service
access is required, ship an explicit disabled-by-default socket, unique
per-device host and operator keys, `-w`, least-privilege/SMACK confinement,
interface allowlisting, firewall policy, and auditable activation.

On a disconnected physical bench, only passive checks are needed initially:
installed file hashes/presence, systemd unit and socket state, process list,
listening sockets, firewall rules, executable xattrs, and effective process
label. Do not attempt authentication merely because a public key file exists.

## Evidence

Reviewed excerpt:
`evidence/artifacts/network-candidates/dropbear-inert-artifacts-evidence.txt`,
SHA-256
`ebe4d28cbf8e0983b80ed110d1882f42ca7da6053f052cb6c9b7396580791a69`.
