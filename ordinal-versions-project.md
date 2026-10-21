# Ordinal: package version ordering and OSV matching, proved, in Ada

*Project document, 21 October 2026. "Ordinal" is a working name, to be
checked before publication.*

> **Status of every claim in this document.**
> - **Read in the specifications**: the OSV schema and its ecosystem list,
>   rpm-version(7) (the RPM comparison rules), Debian Policy's version
>   section, CPE 2.3 naming, the CVE record format, the NVD CVE and CPE
>   API 2.0 schemas.
> - **Measured** (21 October 2026, Linux x86-64): the reference tools
>   installed (`rpm` 4.18.2 and its `rpm.vercmp` through `--eval`,
>   `dpkg --compare-versions`, Python `packaging`), and the Alire index.
>   Appendix A has the commands.
> - **[to confirm]**: the version rules of ecosystems whose specifications
>   were not read (Alpine's apk, PEP 440 in full, Maven, Go's
>   pseudo-versions, npm ranges), and the Package URL specification.
>   Milestone M0 reads them; nothing is built on such a claim before.

---

## 1. Summary

Ordinal answers one question with a guarantee: **is this installed
package, at this version, affected by this vulnerability record?**

It provides:

1. **Version comparators**, one per packaging ecosystem: RPM (epoch,
   version, release, `~` and `^`), Debian (`dpkg`), SemVer 2.0, and later
   PEP 440, Alpine, Maven. Each is **total and proved** in SPARK: any two
   strings give an order, never an exception.
2. **The OSV range engine**: `ECOSYSTEM` and `SEMVER` ranges, the
   `introduced`, `fixed`, `last_affected` and `limit` events, and explicit
   version lists, evaluated with the ecosystem's own comparator.
3. **Ecosystem-scoped matching**: `AlmaLinux:9`, `Debian:12`, `Alpine:v3.16`
   are different ecosystems, and a package is matched against records of
   its own distribution release.
4. **CPE 2.3**: formatted-string parsing and the matching of NVD
   configurations with their version bounds.
5. **Differential testing** against the distributions' own comparators,
   so that "proved total" goes with "agrees with `rpm` and `dpkg`".

---

## 2. The problem

### 2.1 Why version ordering is where vulnerability matching fails

A vulnerability scanner compares an installed version with the ranges of
a record. Each step has a classic failure:

| step | failure | consequence |
|---|---|---|
| comparing versions | a generic comparator applied to RPM or Debian versions: `2.0~beta1` taken as newer than `2.0`, `1:1.0` as older than `2.0`, `1.0-5` as equal to `1.0` | false negatives and false positives both |
| choosing the ranges | **upstream ranges applied to a distribution package**: the distribution backports the fix into `1.2.3-4.el9_1` while upstream says "fixed in 1.2.5" | every backported fix reported as a vulnerability: the scanner is noise, and is turned off |
| reading the record | `last_affected` treated as `fixed`, `limit` ignored, `introduced: "0"` mishandled | wrong boundaries |
| the ecosystem | a record for `Debian:11` applied to `Debian:12`, or `Red Hat` records to AlmaLinux | wrong matches |
| a malformed version | the comparator raises or loops on a string nobody expected (a vendor's `1.0-rc1+git.abc` in an RPM) | the scan stops, or the package is silently skipped |

The second row is the decisive one. On an enterprise Linux system,
upstream version numbers say almost nothing about fixes. The only correct
match is against the distribution's own advisories, compared with the
distribution's own ordering. OSV publishes those advisories per ecosystem
and release (`AlmaLinux:9`, `Rocky Linux:9`, `Debian:12`, ...), which makes
a correct scanner possible, provided the comparator is exactly the
distribution's.

### 2.2 What exists (measured in the Alire index)

`semantic_versioning` (SemVer in Ada), `spdx` and `spdx_tool` (licence
expressions), and JSON readers (`json`, `vss`, `aor_jsona`). **Nothing
compares RPM or Debian versions, evaluates OSV ranges, or parses CPE.**

### 2.3 Why prove it

A comparator is a total function over strings an attacker or a vendor
controls (package metadata is not trusted input in a scanner). The
classic implementations are loops with several indices over two strings,
which is where an off-by-one or an unbounded integer conversion hides. A
digit run of fifty characters must compare correctly, without overflow
and without exception. That is a numeric-bound property, and SPARK proves
it.

---

## 3. Goals and non-goals

### Goals

1. **Comparators exactly equal to the reference implementations**, for
   every input: proved total, and agreeing with `rpm` and `dpkg` on
   millions of generated and real versions.
2. **The OSV evaluation exactly as the schema defines it**, including
   multiple ranges, multiple `introduced` events, `limit` events, and the
   explicit `versions` list.
3. **Ecosystem awareness**: the comparator is chosen by the record's
   ecosystem, and the scope by the release suffix.
4. **CPE 2.3**: parse a formatted string into its eleven attributes with
   the escaping rules, and match NVD configurations
   (`versionStartIncluding`, `versionEndExcluding`, ...) **[to confirm the
   field names against the NVD CVE API 2.0 schema]**.
5. **No allocation in the comparators**, so they can be used anywhere;
   the record engine may use bounded containers.
6. **Explainable answers**: a match says which record, which range,
   which event bounded it, and the two comparisons that decided.

### Non-goals

- Fetching or storing vulnerability databases. Ordinal evaluates records
  the caller supplies.
- Reading the package database of a system (rpmdb, dpkg status). The
  caller supplies installed names and versions. Adapters may come later.
- `GIT` ranges (commit ancestry): they need a repository, out of scope.
- Severity scoring. CVSS is a separate concern.

---

## 4. The rules, from the specifications

### 4.1 RPM (rpm-version(7))

- **Epoch** compared numerically first; an absent epoch is 0: `5:3.0-1`
  is newer than `4:6.0-1` and than `6.0-1`.
- **Version**, then **release**, each compared segment by segment, left to
  right. Separators (`.`, `_`, `+`) only separate: `1.0`, `1+0` and
  `1+.+0` are equal.
- Segments are **digit runs**, compared numerically with leading zeros
  ignored, or **letter runs**, compared lexicographically.
- **`~` sorts older**: `2.0~beta1` < `2.0~rc1` < `2.0`.
- **`^` sorts newer than the base but older than the next version**:
  `2.0` < `2.0^20250611` < `2.0.1` (measured with `rpm.vercmp`: `2.0^1`
  vs `2.0.1` gives -1).
- **Release present on one side only**: compared only when both have
  it. The specification's example: `1.0-5` is newer than `1.0` and
  `1.0-1` **[to confirm the exact rule for a missing release in a
  comparison, since a range bound often has no release]**.

### 4.2 Debian (Policy, version section)

- `[epoch:]upstream_version[-debian_revision]`; epoch numeric first.
- `upstream_version` and `debian_revision` compared by alternating
  non-digit and digit parts. In the non-digit parts, **`~` sorts before
  everything, even the end of the part**, and letters sort before
  non-letters. Digit parts are compared numerically.
- An absent `debian_revision` is `0`.
- Measured: `dpkg --compare-versions 1.0~rc1 lt 1.0` is true.

### 4.3 OSV ranges (schema)

- `ranges[].type` is `ECOSYSTEM`, `SEMVER` or `GIT`.
- `events` is a timeline: `introduced`, `fixed`, `last_affected`,
  `limit`; one key per event object.
- `introduced: "0"` sorts before every version; `limit: "*"` is
  infinity, and is assumed when no `limit` event is given; several
  `limit` events are allowed.
- `fixed` is the first version with the fix (the range excludes it);
  `last_affected` is the last known affected version (the range includes
  it). `fixed` is preferred.
- `affected[].versions` lists affected versions explicitly, to be
  matched as well.

The **evaluation algorithm** (sorting the events with the ecosystem's
comparator, walking them, and the exact role of `limit`) is to be quoted
from the schema's own pseudo-code before M3 **[to confirm]**: the summary
read so far does not give it to the letter, and this is the place where
an approximation costs false negatives.

### 4.4 Ecosystems

Read in the OSV ecosystem list: `AlmaLinux:<release>`, `Rocky Linux`,
`Red Hat`, `Debian:<release>`, `Ubuntu`, `Alpine:v<release>`, `PyPI`, `npm`,
`crates.io`, `Go`, `Maven`. The release suffix scopes a record to a
distribution release.

| ecosystem family | comparator | milestone |
|---|---|---|
| AlmaLinux, Rocky Linux, Red Hat, openSUSE **[to confirm]** | RPM | M1 |
| Debian, Ubuntu | Debian | M1 |
| crates.io, npm, Go (modules) | SemVer 2.0 (+ Go's pseudo-versions **[to confirm]**) | M4 |
| PyPI | PEP 440 **[to read]** | M5 |
| Alpine | apk **[to read]** | M5 |
| Maven | Maven's ordering **[to read]** | M6 |

### 4.5 CPE 2.3

The formatted string `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`,
with `*` (ANY) and `-` (NA), and backslash escaping of special characters.
Matching compares attribute by attribute, and NVD configurations add
version bounds.

---

## 5. Architecture

```
  ┌───────────────────────────── caller ─────────────────────────────────────┐
  │  installed packages (ecosystem, name, version)   records (OSV, NVD)      │
  └───────────────┬───────────────────────────────────────▲──────────────────┘
                  │                                       │ Match reports
  ┌───────────────┴──────── Ordinal.Match ────────────────┴──────────────────┐
  │  index records by (ecosystem, name); choose comparator; evaluate ranges  │
  └───────┬───────────────────────────┬──────────────────────────────────────┘
          │                           │
  ┌───────┴──────── Ordinal.OSV ──┐  ┌┴──────── Ordinal.CPE ────────────────┐
  │  Range, Event, evaluation     │  │  parse, escape, match, NVD bounds    │
  └───────┬───────────────────────┘  └┬─────────────────────────────────────┘
          │                           │
  ┌───────┴───────────── Ordinal.Versions (SPARK, proved) ──────────────────┐
  │  RPM   Debian   SemVer   (PEP440   Alpine   Maven later)                │
  │  each: function Compare (L, R : String) return Order                    │
  └─────────────────────────────────────────────────────────────────────────┘
  Optional adapters: Ordinal.OSV.JSON (reads OSV JSON through an existing
  JSON crate), Ordinal.NVD.JSON.
```

### 5.1 The comparators

```ada
type Order is (Less, Equal, Greater);

package Ordinal.Versions.RPM with SPARK_Mode is
   type EVR is record
      Epoch   : Span;   -- into the string; empty means 0
      Version : Span;
      Release : Span;   -- empty means absent
   end record;
   function Split (S : String) return EVR
     with Post => Within (Split'Result, S);
   function Compare (L, R : String) return Order;          -- total
   function Compare_Segment (L, R : String) return Order;  -- rpmvercmp on one field
end Ordinal.Versions.RPM;
```

Digit runs are compared **without converting to an integer**: strip
leading zeros, compare lengths, then compare characters. No overflow is
possible, so a fifty-digit run is fine. Proved total, with
loop variants for termination.

**Order properties**, proved where SPARK can reach them and tested where
it cannot:

| property | statement | proof or test |
|---|---|---|
| reflexive | `Compare (A, A) = Equal` | proved |
| antisymmetric | `Compare (A, B) = Less` iff `Compare (B, A) = Greater` | proved, if tractable; else property-tested |
| transitive | Less(A,B) and Less(B,C) imply Less(A,C) | property-tested on generated triples (proof of transitivity over strings is a research-sized task) |
| consistent with the reference | `Compare (A, B)` = `rpm.vercmp (A, B)` | differential test (§7) |

### 5.2 The OSV engine

```ada
type Event_Kind is (Introduced, Fixed, Last_Affected, Limit);
type Event is record Kind : Event_Kind; Version : Bounded_Version; end record;
type Range_Kind is (Ecosystem, Semver);
type OSV_Range is record
   Kind   : Range_Kind;
   Events : Event_List;   -- bounded
end record;

function Affected (V : String; R : OSV_Range; Cmp : Comparator) return Verdict;
--  Verdict: Affected | Not_Affected | Undetermined (malformed range), with
--  the deciding events recorded for the report.
```

The engine sorts events with `Cmp`, then walks them per the schema's
algorithm (§4.3, quoted before M3). `Undetermined` exists because a
record can be malformed (a `fixed` before its `introduced`), and saying
so is better than guessing.

### 5.3 Matching

```ada
procedure Match (Installed : Package_List; Records : Record_Store;
                 Each : not null access procedure (M : Match_Report));
```

Records are indexed by `(ecosystem with release, package name)`. A
package's ecosystem is given by the caller: from the distribution's
`os-release` **[to confirm the mapping table: ID and VERSION_ID to OSV
ecosystem names]**, and the comparator follows from it. The report holds
the record identifier, its aliases (CVE identifiers), the range and the
deciding events, and the fixed version when one is known: "upgrade to
`1.2.3-4.el9_1`".

### 5.4 CPE

```ada
type CPE_Name is record
   Part, Vendor, Product, Version, Update, Edition, Language,
   SW_Edition, Target_SW, Target_HW, Other : Attribute;   -- Any | NA | Value(span)
end record;
procedure Parse (S : String; Name : out CPE_Name; OK : out Boolean);  -- proved total
function Matches (Pattern, Candidate : CPE_Name) return Boolean;
function In_Bounds (V : String; Bounds : NVD_Bounds; Cmp : Comparator) return Boolean;
```

The version comparison in NVD bounds needs a comparator too, and the right
one is rarely known (NVD versions are upstream strings). Ordinal uses a
documented "generic dotted" comparator there, and marks such matches as
lower confidence in the report. An upstream-range match is never
presented as equal to a distribution-advisory match.

---

## 6. Proof plan

| unit | property | level |
|---|---|---|
| `Versions.RPM`, `Versions.Debian`, `Versions.SemVer` | total, no overflow, terminates; reflexive; spans inside the input | silver plus gold postconditions |
| `CPE.Parse` | total; escaping handled; spans inside the input | silver plus gold |
| `OSV` evaluation | total over bounded event lists; `Undetermined` on malformed ranges, never an exception | silver |
| digit-run comparison | correct for any length, by construction (lengths, then characters) | gold: a postcondition equating it to numeric comparison on runs short enough to convert |

---

## 7. Testing beyond proof

1. **Differential against the references**, the heart of the test suite:
   - RPM: `rpm --eval '%{lua: print(rpm.vercmp(a, b))}'` (measured to
     work with `rpm` 4.18.2), batched to amortise process start;
   - Debian: `dpkg --compare-versions` (measured);
   - PEP 440: Python `packaging.version` (measured: `1.0rc1 < 1.0`,
     `1.0.post1 > 1.0`, `1!0.1 > 2.0`);
   - SemVer: the specification's examples, and a reference implementation
     **[to choose]**.
2. **Corpora**: every version string from real repositories: AlmaLinux
   and Debian package indexes, and the versions present in OSV's
   per-ecosystem exports **[to confirm their download form]**. All pairs
   of neighbours in sorted order, plus random pairs.
3. **Generated versions**: a grammar per ecosystem producing tildes,
   carets, epochs, letter runs, long digit runs, empty segments, every
   separator. Every pair is compared by Ordinal and by the reference.
4. **OSV fixtures**: real records with `introduced: "0"`, multiple
   ranges, `last_affected`, `limit`, explicit `versions`, and known
   installed versions with their expected verdicts, taken from the
   distributions' own advisories.
5. **Fuzzing** with the companion fuzzer Harrow: differential oracle
   against `rpm` and `dpkg`, non-vacuity (some pairs must compare unequal).

---

## 8. Examples

- **vercmp**: `ordinal-vercmp rpm 2.0~beta1 2.0` prints `<`, a drop-in
  for scripts.
- **scan-host**: reads the installed package list (an adapter for
  `rpm -qa` output and `dpkg-query` output), the OSV export for the host's
  ecosystem, and prints affected packages with the fixed version.
- **explain**: given a package, a version and a record, prints the sorted
  events and why the verdict is what it is.

---

## 9. Roadmap

| milestone | content | done when |
|---|---|---|
| **M0** reading | OSV's evaluation pseudo-code quoted; the missing-release rule in RPM; PEP 440, apk and Maven rules; Package URL; the os-release to ecosystem table | each [to confirm] answered from its source and the document amended |
| **M1** RPM and Debian | `Versions.RPM`, `Versions.Debian`, proved | silver proof, no justification; 10^6 generated pairs and every neighbouring pair of a real repository index agree with `rpm` and `dpkg`, or each difference is filed and explained |
| **M2** OSV engine | §5.2, with fixtures from real advisories | every fixture's verdict matches the distribution's own statement |
| **M3** matching | §5.3, the index and the reports; `scan-host` | a host's scan agrees with the distribution's own security tool on the same day **[to name the tool per distribution]** |
| **M4** SemVer and its ecosystems | crates.io, npm, Go | the SemVer specification's examples pass; interop with the existing `semantic_versioning` crate examined (reuse it if it is total) |
| **M5** PEP 440 and Alpine | | differential against `packaging` and `apk` **[to measure apk's availability]** |
| **M6** CPE and NVD bounds | §5.4 | CPE 2.3's examples parse and match; NVD configurations evaluated on a sample, lower confidence marked |
| **M7** publication | crate, documentation, examples | a stranger reproduces the differential results |

---

## 10. Risks and open questions

| risk | what shows it | answer |
|---|---|---|
| A corner of `rpmvercmp` behaves differently across rpm versions | differential runs against several rpm releases | test against the rpm versions of each supported distribution release, and document any divergence as data |
| OSV records that are inconsistent | `Undetermined` verdicts counted | report them, never guess |
| Ecosystem names drift (`Red Hat` vs `Red Hat Enterprise Linux`) | unmatched records | the table is data, versioned, with a test per entry |
| Transitivity cannot be proved | proof attempts | property tests on generated triples; documented as tested, not proved |
| Users treat CPE matches as certain | false positives reported upstream | confidence levels in every report, and CPE matches never mixed with advisory matches |
| Licence | the maintainers decide | Apache-2.0 or MIT; the comparators are small enough to be vendored by anyone |

---

## 11. Repository layout

```
ordinal/
  alire.toml
  ordinal.gpr
  src/
    ordinal.ads                       -- Order, Span, Within
    ordinal-versions.ads              -- Comparator access type
    ordinal-versions-rpm.ad[sb]       -- SPARK
    ordinal-versions-debian.ad[sb]    -- SPARK
    ordinal-versions-semver.ad[sb]    -- SPARK
    ordinal-osv.ad[sb]                -- ranges, events, evaluation
    ordinal-ecosystems.ad[sb]         -- names, release suffixes, comparator choice
    ordinal-match.ad[sb]
    ordinal-cpe.ad[sb]                -- SPARK parse; matching; NVD bounds
  adapters/
    ordinal-osv-json.ad[sb]           -- through an existing JSON crate
    ordinal-packages-rpm_qa.ad[sb]  ordinal-packages-dpkg_query.ad[sb]
  tests/
    differential/                     -- rpm, dpkg, packaging drivers
    corpora/                          -- version lists with their source
    osv-fixtures/                     -- records + expected verdicts, sourced
    generated/                        -- the version grammars
  fuzz/                               -- Harrow targets
  examples/
    vercmp/  scan-host/  explain/
  docs/
    rules-rpm.md  rules-debian.md  osv-evaluation.md  ecosystems.md  cpe.md  proof.md
```

---

## Appendix A — measurements behind this document

21 October 2026, Linux x86-64:

```bash
rpm --version                                       # RPM version 4.18.2
rpm --eval '%{lua: print(rpm.vercmp("2.0^1","2.0.1"))}'   # -1
python3 -c "import rpm"                             # not installed: rpm.vercmp via --eval instead
dpkg --compare-versions '1.0~rc1' lt '1.0' && echo ok   # ok
python3 -c "import packaging.version as v; print(v.Version('1.0rc1') < v.Version('1.0'))"   # True
python3 -c "...; print(v.Version('1.0.post1') > v.Version('1.0'), v.Version('1!0.1') > v.Version('2.0'))"  # True True
alr search --crates | grep -i -E 'semver|version|osv|cve|vuln|cpe|purl|sbom|spdx|json'
#   semantic_versioning, spdx, spdx_tool, json, vss, aor_jsona ...;
#   nothing for RPM or Debian ordering, OSV or CPE
```
