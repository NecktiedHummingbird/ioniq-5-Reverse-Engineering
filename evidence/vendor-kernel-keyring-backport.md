# Vendor kernel keyring assessment — CVE-2016-0728

Date: 2026-11-01
Target: recovered EU `260128` Linux `4.1.27-abl`

## Result

CVE-2016-0728 is not a viable candidate against the recovered kernel. Although
`CONFIG_KEYS=y` and the affected keyring API is present, exact disassembly shows
the one-reference cleanup added by upstream commit
`23567fd052a9abb6d67fe8e7a9ccdd9800a540f2`.

## Exact evidence

Recovered `join_session_keyring` begins at `0xffffffff811b63d1`. After locating
the named keyring, the shipped function compares it with the new credentials'
current session keyring:

```text
ffffffff811b649e  cmp rax, qword ptr [r13+0x58]
ffffffff811b64a2  jne 0xffffffff811b64b0
ffffffff811b64a4  mov rdi, rax
ffffffff811b64a7  xor ebx, ebx
ffffffff811b64a9  call 0xffffffff811b256b
ffffffff811b64ae  jmp 0xffffffff811b64e6
```

The call target at `0xffffffff811b256b` is the key reference-release helper used
on other keyring cleanup paths. This is the exact branch for
`keyring == new->session_keyring`; it releases the lookup reference before
returning success. That is the complete semantic change in the upstream CVE
fix:

```c
} else if (keyring == new->session_keyring) {
        key_put(keyring);
        ret = 0;
        goto error2;
}
```

Tracked artifacts:

- upstream patch:
  `evidence/artifacts/kernel-candidates/cve-2016-0728-fix.patch`;
- vendor branch:
  `evidence/artifacts/kernel-candidates/kernel-join-session-keyring-branch.asm`;
- input hashes, tool version, and reproduction command:
  `evidence/artifacts/kernel-candidates/README.md`.

## Boundary

This conclusion rejects the specific CVE-2016-0728 reference leak and its
reference-count-overflow exploitation premise. It does not assert that the
vendor keyring subsystem has no other defects. No wraparound or exploitation
probe was run because the exact missing operation is present in the shipped
binary.
