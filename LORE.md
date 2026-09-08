# The Lore of Kadath

KadathSandbox is named for H. P. Lovecraft's *The Dream-Quest of Unknown Kadath*,
in which Randolph Carter journeys through the Dreamlands to the cold waste where
the gods dwell. The tool borrows that world's vocabulary: you bring an untrusted
thing down into a place it cannot leave, you set watchers on it, and you read the
signs of what it did.

This is flavour, not obfuscation. Every term below has a plain security-research
meaning, and the code and docs use whichever word is clearer in context. This page
is the dictionary between the two.

## The glossary

| In the lore | In security terms | Where it lives |
|---|---|---|
| **Kadath** | the isolated sandbox itself — the place a sample is brought and cannot escape | the Docker stack (`make up`) |
| **The Offering** | submitting a sample and detonating it — staging it and triggering it so it runs | `bin/kadath offer`, `make offer`, the **kadath-offer** skill |
| **The Wards** | containment and the operational controls that keep the thing bound | `netguard`, the `gateway`, the hardened `wordpress` container, the **kadath-ward** skill |
| **The Gaunts** | the silent watchers at the lowest level — syscalls, process spawns, file opens, raw connects | the `tracer` sidecar (strace / bpftrace), the **kadath-gaunt** skill |
| **The Omens** | the collected artifacts and telemetry a run leaves behind | `artifacts/` — Xdebug traces, decrypted flows, DNS, pcaps, dumps |
| **The Scrying** | reading the omens — turning the artifacts into a report with IOCs and a verdict | the **kadath-scry** skill, `summary.json` / `iocs.json` |
| **The Pilgrimage** | a batch triage of a whole threat library, case by case, with a local model instead of a human analyst | `bin/kadath pilgrimage`, `make pilgrimage` |
| **The Cavern of Flame** | the static judgment before any detonation — the priests Nasht and Kaman-Thah decide, from the source alone, whether the thing is worthy of being carried down as an Offering | tier 0 of the pilgrimage, `kadath/cavern.py`, `<case>/kadath/cavern.json` |
| **The Deep Scrying** | an agentic re-examination, with read-only tools over the run's omens, of what the Offering left uncertain | tier 2 of the pilgrimage, `kadath/deepscry.py` |
| **The Manifest** | the ledger of the pilgrimage — one row per case, which tier reached, which verdict; kept in the waking tongue | `<library>/kadath-triage.csv` |

## The ritual, told both ways

**In the lore.** You carry the untrusted thing down into Kadath, a waste it has no
road out of. You raise the Wards so it cannot reach the waking world. You lay the
Offering before it and let it stir. The Gaunts watch every motion it makes in the
dark; the Omens gather where it passed. Then you Scry — you read the signs — and
you name what you found.

**In plain terms.** You start the sandbox (an isolated Docker stack with no route to
your machine). Containment holds the sample as an unprivileged, read-only, network-
pinned process. You stage and trigger the sample so its code actually runs. A
privileged tracer records its syscalls while the PHP, network, and packet layers
capture everything else into `artifacts/`. Finally you analyse those artifacts into
a report — call chain, database changes, network, IOCs — and a red / amber / green
verdict.

**The pilgrimage.** When there are thousands of things to judge, the ritual is
walked in passes. Every pilgrim first stands in the Cavern of Flame, where the
priests read it and decide whether it is worth carrying down at all. The worthy
are laid as Offerings, one after another, and their Omens gathered. Those whose
signs stay unclear are taken to the Deep Scrying, where a watcher with tools may
question the Omens directly. The Manifest records every judgment, so a pilgrimage
interrupted resumes where it stopped.

## A note on the names

The **skill names** carry the flavour (`kadath-offer`, `kadath-scry`,
`kadath-gaunt`, `kadath-ward`); their **descriptions** keep the plain trigger words
("offer / run / analyze a WordPress sample…") so an agent still finds the right one
by what it does. The command verb is `offer` (`make offer SAMPLE=…`). Reports still
land under `reports/<slug>-<timestamp>/`, and the verdict is still red / amber /
green — some things are clearer left in the waking tongue.
