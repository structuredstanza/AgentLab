# Vendored privilege-escalation reference data

Generated and vendored so an agent can answer "can this binary escape?" and
"which signed Windows binary does X?" offline, at a pinned version, without
fetching a repository mid-engagement.

| File | Source | Licence | Entries |
|---|---|---|---|
| `gtfobins.json` | [GTFOBins/GTFOBins.github.io](https://github.com/GTFOBins/GTFOBins.github.io) | GPL-3.0 | 458 executables |
| `lolbas.json` | [LOLBAS-Project/LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | MIT | 248 binaries |
| `../scripts/linpeas.sh` | [peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng) release artifact | NOASSERTION | — |

`linpeas.sh` sha256: `37f4ba2301de3c1342fe71d96a51de849e4d2f5fa6de1898dc9b1c8f8839602a`

The upstream repositories are site generators with thousands of files; the
indexes keep only the fields a decision depends on — escape classes, contexts,
categories, and one example command each.

## Regenerating

```sh
git clone --depth 1 --filter=blob:none --sparse https://github.com/GTFOBins/GTFOBins.github.io
cd GTFOBins.github.io && git sparse-checkout set _gtfobins && cd ..
git clone --depth 1 --filter=blob:none --sparse https://github.com/LOLBAS-Project/LOLBAS
cd LOLBAS && git sparse-checkout set yml && cd ..

python3 scripts/build-indexes.py \
    --gtfobins GTFOBins.github.io \
    --lolbas   LOLBAS \
    --out      reference
```

Requires PyYAML. Read the diff before committing: an upstream entry can gain a
new context or category, and the example command is what an agent may copy.

## Refreshing linpeas.sh

```sh
curl -sL -o scripts/linpeas.sh \
  https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sha256sum scripts/linpeas.sh   # update the checksum above
```

Verify the script's first lines and that it is a shell script before committing;
this is executable content that runs on engagement hosts.
