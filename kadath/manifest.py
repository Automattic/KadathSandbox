"""kadath-triage.csv: one row per library case, the pilgrimage's only state.
A pass processes rows whose status for that pass is 'pending'; that is the
whole resume logic. Rewritten atomically after every case."""
import collections
import csv
import datetime
import os

COLUMNS = ["case_id", "php", "sha256", "size",
           "cavern_status", "cavern_verdict", "cavern_family", "cavern_worthy", "cavern_at",
           "offer_status", "offer_verdict", "offer_coverage", "run_dir", "offer_at",
           "scry_status", "scry_verdict", "scry_at",
           "final_verdict", "decided_by", "error"]
PASSES = ("cavern", "offer", "scry")
STATUSES = ("pending", "done", "skipped", "error", "timeout")


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Manifest:
    def __init__(self, path):
        self.path = path
        self.rows = collections.OrderedDict()

    def load(self):
        self.rows = collections.OrderedDict()
        if not os.path.exists(self.path):
            return
        with open(self.path, newline="") as f:
            for r in csv.DictReader(f):
                self.rows[r["case_id"]] = {c: r.get(c, "") or "" for c in COLUMNS}

    def ensure_rows(self, cases):
        for c in cases:
            if c.id in self.rows:
                continue
            row = {col: "" for col in COLUMNS}
            row["case_id"] = c.id
            if c.skip_reason:
                row.update(cavern_status="skipped", offer_status="skipped",
                           scry_status="skipped", error=c.skip_reason)
            else:
                row.update(php=c.php, cavern_status="pending", offer_status="pending",
                           scry_status="pending")
            self.rows[c.id] = row

    def pending(self, pass_name):
        if pass_name not in PASSES:
            raise ValueError(f"unknown pass {pass_name!r}")
        out = []
        for r in self.rows.values():
            if r[f"{pass_name}_status"] != "pending":
                continue
            if pass_name == "offer" and not (r["cavern_status"] == "done" and r["cavern_worthy"] == "true"):
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

    def retry(self, passes, force=False):
        flip = ("error", "timeout", "done") if force else ("error", "timeout")
        for r in self.rows.values():
            for p in passes:
                if r[f"{p}_status"] in flip:
                    r[f"{p}_status"] = "pending"
                    r["error"] = ""

    def flush(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            w.writeheader()
            for r in self.rows.values():
                w.writerow(r)
        try:
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def histogram(self, column):
        h = collections.Counter(r[column] for r in self.rows.values())
        return dict(sorted(h.items()))
