# nftgen — TODO / roadmap

Phases 0–6 are done (skeleton → defs → named sets → rules/chains → host→.nft →
nft -c validation → primitives A–E). What's left, à la carte:

## Safety / validation

- [x] **Strict rule-key validation** (done 2026-06-27). `RuleRenderer.render()`
      now rejects unknown rule keys (`unknown = set(rule) - _KNOWN_RULE_KEYS` →
      `BuildError`), so a typo like `dprot:` fails loudly instead of silently
      rendering a broader rule. `raw:`/`vmap:` must be a rule's only key. Tests:
      `test_unknown_key_errors`, `test_raw_must_be_alone`, `test_vmap_must_be_alone`.

- [x] **Strict authoring surface everywhere** (done 2026-07-05, v0.2.0). The
      rule-level strictness extended to every level after a review found silent
      failure modes that `nft -c` does NOT catch:
      - unknown keys error at policy/table/chain/set/vmap/flowtable level (a
        typo'd `tables:`/`chains:` used to generate a valid **empty** ruleset —
        with the deploy flush prefix, a firewall wipe);
      - a policy with no `tables:` refuses to generate;
      - `iifname`/`oifname`/flowtable devices must be defined interface
        groups (a typo'd
        name used to render a literal `iifname "lan_ifacse"` that deploys and
        never matches — `nft -c` passes it); one-device groups (`eth0: [eth0]`)
        are the literal escape hatch (a self-named item reads as a literal);
      - non-numeric ports must be defined services; named-set refs are
        type-checked (`iifname: <addr set>` used to pass `nft -c`!);
      - groups that resolve to no elements error at use (`iifname { }` passes
        `nft -c` as a dead rule);
      - definition cycles and include cycles error with the chain path
        (previously: silent empty expansion / RecursionError);
      - missing defs dir / site file / include file are clean errors;
      - base-chain `policy:` default is type-aware (`filter` → drop, `nat`/
        `route` → accept — drop on a nat chain drops unmatched new flows);
      - `nftgen build --check` exits 2 loudly when `nft -c` isn't usable
        (used to silently skip validation);
      - CLI prints `nftgen: error: <msg>` (rc 1) for authoring mistakes instead
        of a traceback.

- [ ] **reject nft-keyword set/map names** — a set/map named after an nft keyword
      (`fwd`, `last`, …) breaks the generated ruleset with a confusing parse error.
      Guard against it at build time. (Found while verifying maps; see docs/maps.md.)

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
- [ ] more meta matches (pkttype, skuid, …), `redirect` action, ct mark. (mark
      match + the expanded **vmap keys** — `dport`/`sport`/`mark`/`state`/`saddr`/
      `daddr` + concat `key: [iifname, oifname]` — are done; see docs/maps.md.)

## Output

- [ ] **JSON emitter** (experimented, shelved on branch `json-emitter` — see
      [docs/progress.md](docs/progress.md)) — a second emitter on the same IR
      (libnftables JSON), for
      `nft -j` apply + round-tripping + live `add element`. The IR was built so
      this is additive (Table/Set/Chain/Rule already model the objects).

## Testing & infra

- [x] **Behavioral harness** — done rootless via netns (`tests/behavioral/`,
      B01–B03 green; no VM needed). Matrix breadth (B04+, P01–P20) tracked in
      [PLAN.md](PLAN.md) §R1 / [docs/testing-plan.md](docs/testing-plan.md).
- [x] **own venv** — `make install-dev` (2026-07-09), plus the lint suite +
      pre-commit (`make verify`).
- [x] **dynamic-set meters** — done 2026-07-10. `meter: {set, key, rate,
      timeout}` renders `update @set { <key> [timeout T] limit rate R }` on a
      `flags: [dynamic]` set (keys: saddr/daddr/iifname/oifname). Per-source
      log sampling (best-practices §8d) is now structured, not raw.
      Fail2ban-style throttling uses the same primitive.
- [ ] **opt-in `iif`/`oif` index matching** — faster 32-bit compare for
      static-NIC hosts; unsafe for dynamic interfaces (index changes on
      recreate), so name form stays the default. See best-practices §8a.
- [ ] **CI** — GitHub Actions: `pytest` + `nft -c` + `nftgen build example
      --check` + golden drift + `make lint` (PLAN §R2).

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
      structured (A–E), and document statements / counters / flowtables /
      vmaps / flags / per-table `raw:` in the spec.
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
