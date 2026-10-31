# Plan — exact CVE-2017-6074 DCCPv6 path applicability correction

## Objective

Correct the rejected uncommitted package so it models the specific public
CVE-2017-6074 request path: DCCP core plus the DCCPv6/IPv6 translation unit.
Keep physical component/path findings independent of the public CVE dependency;
reject the CVE only when that dependency and physical named-path absence both
hold, unless positive complete-path evidence exists.

## Baseline and preservation

- Required starting baseline: `5ba7c1d`; verified before correction. Concurrent
  work later advanced the integration base to `8df8d77` and incorporated the
  DCCP changelog block without changing a technical package path.
- Preserve unrelated concurrent changes in
  `tools/uk_fw/ias_backend_soft/micom_service.c` and the untracked
  `tools/uk_fw/ias_backend_soft/micom-service`; do not read, modify, stage, or
  otherwise include them. Do not touch any MICOM/IAS path.
- Do not commit, push, stage, reset, stash, delete, run recovered targets,
  create communication endpoints, construct traffic, or exercise triggers.
- Do not broaden impact or claim dynamic behavior.

## Corrected model contract

1. Use exactly these 15 Boolean facts:
   `public_cve_requires_named_dccpv6_request_path`,
   `public_v4_1_build_rules_applicable`, `ip_dccp_config_enabled`,
   `inet_config_enabled`, `ipv6_config_enabled`, `user_ns_config_enabled`,
   `dccp_core_translation_units_built_in`,
   `dccpv6_translation_unit_built_in`,
   `recovered_module_inventory_complete`,
   `dccp_core_named_modules_shipped`, `dccpv6_named_module_shipped`,
   `queried_named_core_symbols_present`,
   `queried_named_dccpv6_symbols_present`,
   `functional_ipv4_only_dccp_path_present`, and
   `functional_named_dccpv6_request_path_present`.
2. Derive DCCP-core and DCCPv6 physical presence independently of the CVE
   dependency. Exact queried core-symbol presence establishes core
   translation-unit presence; exact queried DCCPv6-symbol presence establishes
   DCCPv6 translation-unit presence. IPv4-only functional evidence establishes
   core presence only. Positive complete DCCPv6 functional evidence establishes
   both components and the complete path and overrides absence.
3. Establish the exact default physical absence from applicable public v4.1
   build rules plus `IP_DCCP=n`, which excludes the whole named DCCP subtree.
   Also permit a formally complete component-specific route: a precise
   no-built-in fact plus a complete recovered-module inventory with no
   corresponding named module. Positive component evidence takes precedence
   and records a conflict; incomplete physical states remain unknown.
4. The specific named request path requires both core and DCCPv6. Without
   positive complete-path evidence, one conclusively absent component is enough
   to establish physical path absence. Component presence alone does not prove
   a functional complete request path.
5. Compute rejection exactly as
   `public CVE dependency && physical named-path absence`. Therefore dependency
   false does not erase physical path or translation-unit outputs.
6. Treat `INET`, `IPv6`, and `USER_NS` as bounded configuration facts. An
   `IPv6=n` input alone does not establish general IPv6 absence. USER_NS is
   non-decisive.
7. Keep unnamed/vendor-equivalent routes, recovered-code fix effects, installed
   identity, runtime reachability/behavior/policy, corruption, privilege gain,
   root, and persistence unknown.

## Evidence and documentation contract

1. Bind the exact recovered kernel, Build ID, configuration, authoritative map,
   canonical decrypted stock archive, public v4.1 Kconfig/Kbuild files, and
   retained mainline/stable patches to their established hashes.
2. State throughout the package and integrations that the specific public path
   requires DCCP core plus DCCPv6/IPv6. Preserve the exact default conclusion:
   applicable public build rules plus `IP_DCCP=n` exclude the whole named
   subtree, and the complete canonical module inventory has no canonical DCCP
   modules.
3. Preserve the complete ten-name exact-row inventory as bounded corroboration,
   separated into queried core and DCCPv6 identities for model inputs.
4. Bind the 15 June 2017 Linux 4.1.41 date only to the retained official
   `ChangeLog-4.1.41` release commit/date. Remove the unretained archive-index
   assertion.
5. Retain the public fix effect only as context; do not claim that effect in
   absent recovered code.

## Directed and exhaustive validation

- Cover dependency false while physical absence remains reported.
- Cover queried core-symbol presence and queried DCCPv6-symbol presence.
- Cover core present with DCCPv6 absent.
- Cover IPv4-only functional evidence.
- Cover positive complete DCCPv6 functional evidence overriding absence.
- Assert every classification field over all `2^15 = 32,768` Boolean states.
- Cover all-or-none CLI behavior, deterministic explicit UTF-8/LF output,
  evidence bindings, release-date source narrowing, and operational-material
  exclusions.
- Recompute every affected recorded hash.
- Run the focused test, bytecode compilation, exact static checks, and
  `git diff --check`; run the complete suite and public harness only after
  corrected independent technical acceptance.

## Orchestration and review status

Generic public research used Astra. This correction's implementation provenance
is the active `codex-router/gpt-daybreak-blue-latest` pi session. The installed
`astra_terra_builder_deepseek_flash` binding is statically ready for
`deepseek/deepseek-v4.1-flash`, but runtime routing is unverified and DeepSeek
did not run. No substitute worker or paid probe is used.

The initial independent review returned **REJECT** for the model-contract and
provenance defects corrected above. Corrected independent rereview returned
**ACCEPT** with no blocking findings. The root then ran the complete suite and
public harness.
