"""Generate and read the per-user migration worksheet (users.csv)."""
import csv
import os

COLUMNS = ["email", "name", "user_type", "groups", "account_count", "migrate", "in_new_domain", "status", "last_updated", "note"]
TYPE_LABEL = {"BASIC_USER_TIER": "Basic", "CORE_USER_TIER": "Core", "FULL_USER_TIER": "Full platform"}
YES = {"y", "yes", "true", "1"}
NO = {"n", "no", "false", "0", ""}


def _safe(v):
    """Stop spreadsheet apps from running a cell that starts with a formula character."""
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def status_of(email, selected, in_target, missing_groups, error):
    if error:
        return "failed"
    if in_target:
        if missing_groups:
            return "partial"
        return "migrated" if selected else "in new domain"
    return "pending" if selected else "not selected"


def build_rows(src, target_emails, choices=None, default="no", target_groups=None, errors=None, now=""):
    """target_groups: {group name: set of member emails} in the new domain; enables the 'partial' status."""
    choices = choices or {}
    errors = errors or {}
    groups, accounts = {}, {}
    for g in src["groups"]:
        for m in g["members"]:
            groups.setdefault(m, []).append(g["name"])
            accounts.setdefault(m, set()).update(x["accountId"] for x in g["grants"] if x.get("accountId"))
    rows = []
    for u in sorted(src["users"], key=lambda u: u["email"]):
        e = u["email"]
        selected = choices.get(e, default) == "yes"
        missing = []
        if target_groups is not None and e in target_emails:
            missing = [g for g in groups.get(e, []) if e not in target_groups.get(g, ())]
        note = errors.get(e) or (f"missing from groups: {'; '.join(sorted(missing))}" if missing else "")
        rows.append({
            "email": e, "name": _safe(u["name"]), "user_type": TYPE_LABEL.get(u["tier"], u["tier"]),
            "groups": _safe("; ".join(sorted(groups.get(e, [])))), "account_count": len(accounts.get(e, ())),
            "migrate": choices.get(e, default), "in_new_domain": "yes" if e in target_emails else "no",
            "status": status_of(e, selected, e in target_emails, missing, errors.get(e)),
            "last_updated": now, "note": _safe(note),
        })
    return rows


def write_csv(path, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8-sig") as f:  # BOM so Excel reads UTF-8
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)  # never leaves a half-written worksheet


def read_choices(path):
    """Return ({email: 'yes'|'no'}, [error strings]). Blank counts as no."""
    choices, errors = {}, []
    with open(path, newline="", encoding="utf-8-sig") as f:
        r = csv.DictReader(f)
        if not r.fieldnames or "email" not in r.fieldnames or "migrate" not in r.fieldnames:
            return {}, ["file must have 'email' and 'migrate' columns"]
        for n, row in enumerate(r, start=2):
            email, v = (row["email"] or "").strip().lower(), (row["migrate"] or "").strip().lower()
            if not email:
                continue
            if v in YES:
                choices[email] = "yes"
            elif v in NO:
                choices[email] = "no"
            else:
                errors.append(f"line {n} ({email}): migrate must be yes or no, got {row['migrate']!r}")
    return choices, errors
