# nftgen — TODO / roadmap

Phases 0–6 are done (skeleton → defs → named sets → rules/chains → host→.nft →
nft -c validation → primitives A–E). What's left, à la carte:

## Safety / validation
- [x] **Strict rule-key validation** (done 2026-06-27). `RuleRenderer.render()`
      now rejects unknown rule keys (`unknown = set(rule) - _KNOWN_RULE_KEYS` →
      `BuildError`), so a typo like `dprot:` fails loudly instead of silently
      rendering a broader rule. `raw:`/`vmap:` must be a rule's only key. Tests:
      `test_unknown_key_errors`, `test_raw_must_be_alone`, `test_vmap_must_be_alone`.

## Promote remaining `raw:` recipes to structured keys
- [ ] **set-dscp** — deferred from Phase 6A because DSCP is family-specific
      (`ip dscp set` vs `ip6 dscp set`). Needs to render per-family (like
      addresses do) or require a family-scoped rule. `raw:` works meanwhile.
- [x] **concatenations** (done 2026-06-27) — structured `concat:`/`proto:`/`tuples:`
      set + `set:` rule; derives type, resolves names, auto-interval, single-family,
      one-element-per-field validation. See [docs/concat-authoring.md](docs/concat-authoring.md),
      `tests/test_concat.py`. Follow-ons: `proto: [tcp,udp]` list, per-row `proto`
      field, family auto-split (`_v4`/`_v6`).
- [ ] **named / reusable maps** — declare a table-level `maps:` (verdict maps,
      or key→value maps for dnat targets); reference from a `vmap:` rule or a
      dnat map. (Phase 6D did inline vmaps only.)
- [ ] more meta matches (mark, pkttype, skuid, …), `redirect` action, ct mark.

## Output
- [ ] **JSON emitter** — a second emitter on the same IR (libnftables JSON), for
      `nft -j` apply + round-tripping + live `add element`. The IR was built so
      this is additive (Table/Set/Chain/Rule already model the objects).

## Testing & infra
- [ ] **Vagrant behavioral harness** — spin a VM, apply the generated `.nft`,
      probe with nc/curl/nmap. This validates *semantics* (does the firewall
      behave), not just `nft -c` syntax. The real-trust test.
- [ ] **own venv + CI** — the repo currently borrows the aerleon `.venv` for
      dev. Give it its own venv; add CI that runs `pytest` and `nft -c` (the 3
      skipped validation tests light up on a box with nftables).

## DX / polish
- [ ] **bare-set ergonomics (low priority, YAGNI for now).** Idea: let a bare set
      *infer* its `type` from the elements and control the backend with
      `interval: false` (defaults true) instead of restating `type: ipv4_addr`.
      Snags: empty/live sets (no elements) can't infer a type so `type:` stays
      required there; `interval: false` needs a guard (CIDR/range elements still
      force interval). Only buys hash-vs-interval, which is unmeasurable at our
      scale — the explicit `type:` bare set already covers it. Revisit if it
      becomes common.
- [ ] **nftgen JSON schema** for def + policy files. Right now the editor
      mis-applies *Aerleon's* schema (the bogus "Missing property terms" /
      "Network Definition" errors all over the example). A schema fixes that and
      gives autocompletion.
- [ ] update **DESIGN.md / RAW.md** to mark which `raw:` recipes are now
      structured (A–E), and document statements / counters / flowtables / vmaps /
      flags / per-table `raw:` in the spec.
- [ ] **multi-site / `local`** is built in the defs loader (Phase 1) and wired
      via `site:` (Phase 4). Possible later: layered scopes (`site:` as a list →
      global → region → site), and an inline per-host `local:` override.

## Notes / decisions already made (don't re-litigate)
- Mirror nftables structure; author your own chains; no optimizer.
- A definition becomes a **named set** only when listed under a table's `sets:`;
  else it inlines. Named set = single family (mixed → error, split `_v4`/`_v6`).
- Services carry proto (`22/tcp`) but emit a proto-agnostic `inet_service` set;
  the rule states the proto (kills the tcp/udp cross-product footgun).
- `raw:` (per-rule and per-table) is the escape hatch — nothing is ever blocked.
- ct state is authored, never auto-injected; counters only where you ask.
