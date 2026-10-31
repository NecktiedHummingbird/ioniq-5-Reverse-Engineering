# Checkpoint — exact CVE-2016-9806 netlink dump ownership audit

## Result

CVE-2016-9806 is rejected for the exact recovered kernel by equivalent backport
effects. Complete exact `netlink_dump` machine code captures `cb->module` and
`cb->skb` while holding the callback mutex, clears `cb_running`, unlocks, then
passes only those saved register values to exact `module_put` and `consume_skb`.
It does not reload the reusable callback fields after unlock.

## Exact evidence

- Recovered `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- `CONFIG_NET=y`
- Authoritative embedded-kallsyms map:
  `work/eu-260128/kallsyms.tsv`
- Embedded-kallsyms map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- Complete embedded-kallsyms range, also checked against the ELF's embedded
  address vector:
  `[0xffffffff814a74f7,0xffffffff814a7741)`
- Exact assembly SHA-256:
  `5c6e5e86076843d7844cde807f58dc3e74294749be962642ac3198597055d9ab`
- Upstream patch SHA-256:
  `89638f347ae53c86e2d346da8422ac3e33251fc25230c071376a4874a2d41680`
- Deterministic schema-v2 model report SHA-256:
  `76a84531d28215fa7a690bb8d66c27badc8e12825f563a5e94c9938e6f2dca09`

## Claim boundary

The exact old-versus-new callback-skb cleanup race is absent. In the bounded
model, incomplete saved-object facts now leave the vulnerable reload premise
unknown rather than claiming it present; absence of a fix fact is not evidence
of a mutable callback-field reload. Installed-kernel identity, runtime netlink
reachability, concurrent replacement, double free, crash, unrelated
corruption, privilege gain, root and persistence remain unobserved. This
rejection does not generalize to unrelated netlink defects.

## Safety

No socket, message, dump request, thread, race, target execution, crash,
corruption, privilege transition, or persistence action was created.

## Validation/review

- Focused model validation: `9 passed, 136 subtests passed`.
- Complete suite: `500 passed, 135103 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Python compilation and `git diff --check`: passed.
- Independent instruction/model/provenance review: **ACCEPT** after the schema-v2
  unknown-state and authoritative-kallsyms refinements; no remaining issue.
