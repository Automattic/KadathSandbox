"""kadath-triage.csv: one row per library case, the pilgrimage's only state.
A pass processes rows whose status for that pass is 'pending'; that is the
whole resume logic. Rewritten atomically after every case."""
import collections
import csv
import datetime
import os
import sys

COLUMNS = ["case_id", "php", "sha256", "size",
           "cavern_status", "cavern_verdict", "cavern_family", "cavern_worthy", "cavern_at",
           "runes_status", "runes_verdict", "runes_at",
           "offer_status", "offer_verdict", "offer_coverage", "run_dir", "offer_at",
           "scry_status", "scry_verdict", "scry_at",
           "final_verdict", "decided_by", "error"]
PASSES = ("cavern", "runes", "offer", "scry")
STATUSES = ("pending", "done", "skipped", "error", "timeout")


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Manifest:
    def __init__(self, path, backup=None):
        self.path = path
        # a mirror kept OUTSIDE the library so a git clean -fdx (or any nuke) of
        # the library repo cannot cost the whole run's progress ledger
        self.backup = backup
        self.rows = collections.OrderedDict()

    def load(self):
        self.rows = collections.OrderedDict()
        src = self.path
        if not os.path.exists(src):
            if self.backup and os.path.exists(self.backup):
                print(f"warning: {self.path} gone; restoring the ledger from {self.backup}", file=sys.stderr)
                src = self.backup
            else:
                return
        with open(src, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fields = reader.fieldnames or []
            # Accept an older, shorter schema (columns added by a later version)
            # as long as every column is known and in COLUMNS order; fill the
            # missing ones with "". Reject unknown or reordered columns — those
            # signal a corrupted or hand-mangled file, not a version skew.
            unknown = [c for c in fields if c not in COLUMNS]
            if unknown or list(fields) != [c for c in COLUMNS if c in fields]:
                raise ValueError(f"{src}: unexpected manifest columns {fields}; "
                                 f"expected a subset of {COLUMNS} in order")
            if not fields and os.path.getsize(src) > 0:
                raise ValueError(f"{src}: manifest has no header row")
            for r in reader:
                row = {c: r.get(c, "") or "" for c in COLUMNS}
                # a row from a pre-runes schema has runes_status ""; make it
                # resumable — a worthy done-cavern row is pending for the runes
                # pass, a skipped/non-worthy one stays skipped
                if row["runes_status"] == "":
                    row["runes_status"] = ("skipped" if row["cavern_status"] == "skipped"
                                           or row["cavern_worthy"] == "false" else "pending")
                self.rows[r["case_id"]] = row

    def ensure_rows(self, cases):
        for c in cases:
            if c.id in self.rows:
                continue
            row = {col: "" for col in COLUMNS}
            row["case_id"] = c.id
            if c.skip_reason:
                row.update(cavern_status="skipped", runes_status="skipped",
                           offer_status="skipped", scry_status="skipped", error=c.skip_reason)
            else:
                row.update(php=c.php, cavern_status="pending", runes_status="pending",
                           offer_status="pending", scry_status="pending")
            self.rows[c.id] = row

    def pending(self, pass_name):
        if pass_name not in PASSES:
            raise ValueError(f"unknown pass {pass_name!r}")
        out = []
        for r in self.rows.values():
            if r[f"{pass_name}_status"] != "pending":
                continue
            if pass_name == "runes" and not (r["cavern_status"] == "done" and r["cavern_worthy"] == "true"):
                continue
            if pass_name == "offer" and not (r["cavern_status"] == "done"
                                             and r["cavern_worthy"] == "true"
                                             and r["runes_status"] == "done"):
                continue
            if pass_name == "scry" and not (r["offer_status"] == "done" and
                                            r["offer_verdict"] in ("amber", "red")):
                continue
            out.append(r)
        return out

    def update(self, case_id, **fields):
        row = self.rows[case_id]
        for k, v in fields.items():
            if k not in COLUMNS:
                raise KeyError(k)
            row[k] = "" if v is None else str(v)

    def retry(self, passes, force=False, case_ids=None):
        flip = ("error", "timeout", "done") if force else ("error", "timeout")
        for r in self.rows.values():
            if case_ids is not None and r["case_id"] not in case_ids:
                continue
            for p in passes:
                if r[f"{p}_status"] in flip:
                    r[f"{p}_status"] = "pending"
                    r["error"] = ""

    def _write(self, path):
        tmp = path + ".tmp"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            w.writeheader()
            for r in self.rows.values():
                w.writerow(r)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def flush(self):
        self._write(self.path)
        if self.backup:
            try:
                self._write(self.backup)
            except OSError as e:
                print(f"warning: manifest backup to {self.backup} failed: {e}", file=sys.stderr)

    def histogram(self, column):
        h = collections.Counter(r[column] for r in self.rows.values())
        return dict(sorted(h.items()))
