#!/usr/bin/env python3
"""Replicate users, groups, memberships and role grants from one New Relic authentication domain to another.

  migrate.py domains
  migrate.py preflight --source SRC_ID --target DST_ID               # check key, domains and API before starting
  migrate.py prepare --source SRC_ID --target DST_ID                 # export + generate out/users.csv
  migrate.py export  --domain SRC_ID --out out/source.json
  migrate.py users-csv --domain DST_ID                               # refresh the worksheet, keep choices
  migrate.py apply   --domain DST_ID --in out/source.json --users-csv out/users.csv [--execute]
  migrate.py apply   --domain DST_ID --in out/source.json            # dry run
  migrate.py apply   --domain DST_ID --in out/source.json --execute  # writes
  migrate.py verify  --domain DST_ID --in out/source.json
  migrate.py rollback --domain DST_ID --manifest <file>                               # dry run
  migrate.py rollback --domain DST_ID --manifest <file> --execute                     # undo
  migrate.py rollback --domain DST_ID --manifest <file> --users-csv out/users.csv     # only migrate=no users it created

`apply` never deletes; it only creates what is missing. `rollback` removes only what a manifest from `apply --execute` lists.
Every run writes a detailed log to out/logs/.
"""
import argparse
import json
import logging
import math
import os
import sys
import time

import nrgql
import userlist

__version__ = "1.0.0"

TIERS = {"basic": "BASIC_USER_TIER", "core": "CORE_USER_TIER", "full": "FULL_USER_TIER"}
CHUNK = 50
LOG = logging.getLogger("migrator")


# ---------------------------------------------------------------- logging and progress

def setup_logging(cmd, log_dir):
    """Console shows progress and results (INFO). The log file also gets every object touched and every API call (DEBUG)."""
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, time.strftime(f"{cmd}-%Y%m%d-%H%M%S.log"))
    root = logging.getLogger("migrator")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    fh = logging.FileHandler(path)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(logging.Formatter("%(message)s"))
    ch.setLevel(logging.INFO)
    root.addHandler(fh)
    root.addHandler(ch)
    os.chmod(path, 0o600)
    return path


def say(msg):
    """User-facing result line: printed, and kept in the log file."""
    print(msg)
    LOG.debug("OUTPUT %s", msg)


class Progress:
    def __init__(self, label, total):
        self.label, self.total, self.done = label, total, 0
        self.t0 = self.last = time.monotonic()

    def tick(self, n=1):
        self.done += n
        now = time.monotonic()
        if self.done >= self.total or self.done % 100 == 0 or now - self.last >= 30:
            self.last = now
            rate = self.done / max(now - self.t0, 1e-9)
            left = (self.total - self.done) / rate / 60 if rate else 0
            LOG.info("  %s: %d/%d (%.1f/s, about %.0f min left)", self.label, self.done, self.total, rate, left)


class AbortRun(Exception):
    pass


class Failures:
    """Collects failures; stops the run after too many in a row (for example an expired key or missing permission)."""

    def __init__(self, limit):
        self.items, self.streak, self.limit = [], 0, limit

    def ok(self):
        self.streak = 0

    def add(self, msg):
        self.items.append(msg)
        self.streak += 1
        LOG.error("FAILED %s", msg)
        if self.limit and self.streak >= self.limit:
            raise AbortRun(f"Stopped after {self.streak} failures in a row. Fix the cause (the last error is above), "
                           f"then run the same command again; finished work is kept.")


def write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---------------------------------------------------------------- helpers

def tier_of(display_name):
    n = (display_name or "").lower()
    for key, tier in TIERS.items():
        if n.startswith(key):
            return tier
    return None


def email_of(rec):
    return (rec.get("email") or "").strip().lower()


def grant_key(g):
    return (g["roleId"], g.get("accountId"), g.get("organizationId"), g.get("groupName"), g.get("dataAccessPolicyId"))


def norm_grant(r, id_to_name):
    """API role record -> portable grant. Group-scoped grants (e.g. Group Admin) refer to a group by name,
    because group IDs differ between domains."""
    gid = r.get("groupId")
    return {"roleId": r["roleId"], "roleName": r.get("displayName") or r.get("name"),
            "accountId": r.get("accountId"), "organizationId": r.get("organizationId"),
            "groupName": id_to_name.get(gid) if gid else None, "groupId": gid,
            "dataAccessPolicyId": r.get("dataAccessPolicyId")}


class Manifest:
    """Append-only JSON-lines record of everything `apply --execute` created, written after each successful call."""

    def __init__(self, path, domain_id):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.f = open(path, "a")
        os.chmod(path, 0o600)
        self.add(op="start", domain=domain_id)

    def add(self, **event):
        self.f.write(json.dumps(event) + "\n")
        self.f.flush()


def load_manifest(path):
    events = [json.loads(line) for line in open(path) if line.strip()]
    undone = {e["undone"] for e in events if "undone" in e}
    gone = {e["undone_user"] for e in events if "undone_user" in e}  # users already removed individually
    domain = next(e["domain"] for e in events if e.get("op") == "start")
    out = []
    for i, e in enumerate(events):
        op = e.get("op")
        if op in (None, "start") or i in undone or (op == "user" and e["id"] in gone):
            continue
        if op == "member":
            ids = [u for u in e["userIds"] if u not in gone]
            if not ids:
                continue
            e = {**e, "userIds": ids}
        out.append((i, e))
    return domain, out


def load_export(path):
    """Read an export file, with a clear message instead of a traceback if it is missing or not an export."""
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        sys.exit(f"Export file {path} not found. Run `prepare` (or `export`) first, or pass --in.")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        sys.exit(f"{path} is not a valid export ({e}). Run `export` again.")
    if not (isinstance(data, dict) and {"domain", "users", "groups"} <= data.keys()
            and isinstance(data["domain"], dict) and "id" in data["domain"]):
        sys.exit(f"{path} is not an export written by this tool. Run `export` again.")
    if data.get("tool_version") != __version__:
        LOG.warning("%s was written by version %s; this is %s. Run `export` again if anything looks wrong.",
                    path, data.get("tool_version", "unknown"), __version__)
    return data


def find_domain(client, domain_id, role):
    dom = next((d for d in nrgql.list_domains(client) if d["id"] == domain_id), None)
    if not dom:
        sys.exit(f"{role} authentication domain {domain_id} not found (run `domains` to list them)")
    return dom


def is_scim(dom):
    return "SCIM" in (dom.get("provisioningType") or "").upper()


def confirm_execute(client, domain_id, action, yes, src_name=None):
    """Show which domains will be changed and require the target name to be typed, unless --yes."""
    dom = find_domain(client, domain_id, "Target")
    say(f"About to {action} in: {dom['name']} ({domain_id}, {dom.get('provisioningType')})"
        + (f"\n  Copying from:   {src_name}" if src_name else ""))
    if yes:
        return dom
    if not sys.stdin.isatty():
        sys.exit("Not an interactive terminal: add --yes to confirm that the domain above is correct.")
    if input("Type the target domain name to continue: ").strip() != dom["name"]:
        sys.exit("Name did not match; nothing was changed.")
    return dom


def preflight(client, source_id, target_id):
    """Check key, domains and API support without writing anything. Returns the number of failed checks."""
    bad = 0

    def report(ok, msg):
        nonlocal bad
        bad += not ok
        say(("PASS  " if ok else "FAIL  ") + msg)

    try:
        doms = {d["id"]: d for d in nrgql.list_domains(client)}
    except nrgql.NerdGraphError as e:
        report(False, f"API key / connection: {e}")
        return bad
    report(True, f"API key works; {len(doms)} authentication domains visible")
    report(source_id != target_id, "source and target are different domains")
    for role, did in (("source", source_id), ("target", target_id)):
        d = doms.get(did)
        report(bool(d), f"{role} domain {did}" + (f": {d['name']} ({d.get('provisioningType')})" if d else " not found"))
    if target_id in doms and is_scim(doms[target_id]):
        say("NOTE  target is SCIM-managed: use --no-users (groups and grants only); users come from SCIM")
    for role, did in (("source", source_id), ("target", target_id)):
        if did in doms:
            try:
                nrgql.read_groups(client, did)
                report(True, f"can read groups of the {role} domain")
            except nrgql.NerdGraphError as e:
                report(False, f"cannot read groups of the {role} domain: {str(e)[:200]}")
    try:
        problems = nrgql.check_rollback_schema(client)
        report(not problems, "rollback calls available in this NerdGraph schema" + ("".join(f"; {p}" for p in problems)))
    except nrgql.NerdGraphError as e:
        report(False, f"schema check: {str(e)[:200]}")
    return bad


# ---------------------------------------------------------------- export

def export(client, domain_id):
    dom = next((d for d in nrgql.list_domains(client) if d["id"] == domain_id), None)
    if not dom:
        sys.exit(f"Authentication domain {domain_id} not found")
    LOG.info("Reading users of %s (%s)...", dom["name"], domain_id)
    users = []
    for u in nrgql.read_users(client, domain_id):
        e = email_of(u)
        if not e:
            LOG.warning("Skipping user %s: no email address", u.get("id"))
            continue
        type_name = (u.get("type") or {}).get("displayName")
        tier = tier_of(type_name)
        if tier is None:
            LOG.warning("User %s has an unrecognised user type %r; it will not be created", e, type_name)
        users.append({"id": u["id"], "email": e, "name": u.get("name") or e, "tier": tier, "typeName": type_name})
    LOG.info("  %d users", len(users))
    src_groups = nrgql.read_groups(client, domain_id)
    names = [g["displayName"] for g in src_groups]
    for n in sorted({n for n in names if names.count(n) > 1}):
        LOG.warning("Group name %r appears %d times; the copy merges them into one group", n, names.count(n))
    id_to_name = {g["id"]: g["displayName"] for g in src_groups}
    groups = []
    prog = Progress("groups read", len(src_groups))
    for g in src_groups:
        members = sorted({email_of(m) for m in nrgql.read_members(client, domain_id, g["id"])} - {""})
        grants = [norm_grant(r, id_to_name) for r in nrgql.read_grants(client, domain_id, g["id"])]
        groups.append({"name": g["displayName"], "members": members, "grants": grants})
        LOG.debug("group %r: %d members, %d grants", g["displayName"], len(members), len(grants))
        prog.tick()
    return {"domain": {"id": dom["id"], "name": dom["name"]}, "users": users, "groups": groups,
            "tool_version": __version__, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S")}


# ---------------------------------------------------------------- apply

def snapshot_target(client, domain_id):
    users = {email_of(u): u["id"] for u in nrgql.read_users(client, domain_id)}
    groups = {}
    raw = nrgql.read_groups(client, domain_id)
    id_to_name = {g["id"]: g["displayName"] for g in raw}
    for g in raw:
        groups[g["displayName"]] = {
            "id": g["id"],
            "members": {email_of(m) for m in nrgql.read_members(client, domain_id, g["id"])},
            "grants": {grant_key(norm_grant(r, id_to_name)) for r in nrgql.read_grants(client, domain_id, g["id"])},
        }
    return users, groups


def _recover_group(client, domain_id, name):
    """After an 'outcome unknown' error, find out whether the group was in fact created."""
    for g in nrgql.read_groups(client, domain_id):
        if g["displayName"] == name:
            return g["id"]


def _recover_user(client, domain_id, email):
    for u in nrgql.read_users(client, domain_id):
        if email_of(u) == email:
            return u["id"]


def drop_groups(src, skip_empty_groups=False, skip_no_access=False):
    """Copy of the export without groups that have no members and/or no role grants."""
    if not (skip_empty_groups or skip_no_access):
        return src
    keep = [g for g in src["groups"]
            if not (skip_empty_groups and not g["members"]) and not (skip_no_access and not g["grants"])]
    LOG.info("Skipping %d of %d groups (empty / no access)", len(src["groups"]) - len(keep), len(src["groups"]))
    return {**src, "groups": keep}


def apply(client, domain_id, src, execute, with_users, exclude_roles, only_groups, only_users=frozenset(),
          manifest=None, errors=None, max_consecutive_failures=10, skip_empty_groups=False, skip_no_access=False):
    errors = {} if errors is None else errors
    src = drop_groups(src, skip_empty_groups, skip_no_access)
    skip_roles = {r.lower() for r in exclude_roles}
    LOG.info("Reading the target domain...")
    tgt_users, tgt_groups = snapshot_target(client, domain_id)
    stats = dict(groups=0, grants=0, users=0, memberships=0)
    fails = Failures(max_consecutive_failures)
    warnings = []
    broken_groups = set()
    try:
        _apply(client, domain_id, src, execute, with_users, skip_roles, only_groups, only_users, manifest,
               errors, tgt_users, tgt_groups, stats, fails, warnings, broken_groups)
    except AbortRun as e:
        LOG.error("%s", e)
        warnings.append(f"ABORTED: {e}")
        stats["aborted"] = True
    return stats, fails.items, warnings


def _apply(client, domain_id, src, execute, with_users, skip_roles, only_groups, only_users, manifest,
           errors, tgt_users, tgt_groups, stats, fails, warnings, broken_groups):
    # 1. groups
    src_groups = [g for g in src["groups"]
                  if (not only_groups or g["name"] in only_groups)
                  and (not only_users or only_users & set(g["members"]))]
    todo = [g for g in src_groups if g["name"] not in tgt_groups]
    LOG.info("Groups: %d to create, %d already exist", len({g["name"] for g in todo}), len(src_groups) - len(todo))
    for g in todo:
        if g["name"] in tgt_groups:  # duplicate name in the source
            continue
        stats["groups"] += 1
        if not execute:
            gid = f"dry:{g['name']}"
        else:
            try:
                gid = nrgql.create_group(client, domain_id, g["name"])
                fails.ok()
            except nrgql.NerdGraphError as e:
                gid = _recover_group(client, domain_id, g["name"]) if nrgql.OUTCOME_UNKNOWN in str(e) else None
                if not gid:
                    stats["groups"] -= 1
                    broken_groups.add(g["name"])
                    fails.add(f"group {g['name']}: {e}")
                    for m in g["members"]:
                        errors.setdefault(m, f"group {g['name']} could not be created: {e}"[:300])
                    continue
                LOG.warning("Group %r was created although the call reported an error; recorded it", g["name"])
            LOG.debug("created group %r -> %s", g["name"], gid)
            if manifest:
                manifest.add(op="group", id=gid, name=g["name"])
        tgt_groups[g["name"]] = {"id": gid, "members": set(), "grants": set()}

    # 2. grants (role IDs are organization-level, so they are valid in the target domain unchanged)
    prog = Progress("groups granted", len(src_groups))
    for g in src_groups:
        prog.tick()
        if g["name"] in broken_groups or g["name"] not in tgt_groups:
            continue
        t = tgt_groups[g["name"]]
        want = [x for x in g["grants"]
                if (x["roleName"] or "").lower() not in skip_roles and grant_key(x) not in t["grants"]]
        acct, org, grp = [], {}, []
        for x in want:
            if x.get("accountId"):
                a = {"accountId": int(x["accountId"]), "roleId": x["roleId"]}
                if x.get("dataAccessPolicyId"):
                    a["dataAccessPolicyId"] = x["dataAccessPolicyId"]
                acct.append(a)
            elif x.get("groupId") or x.get("groupName"):
                target = tgt_groups.get(x.get("groupName"))
                if target:
                    grp.append({"groupId": target["id"], "roleId": x["roleId"]})
                else:
                    warnings.append(f"SKIPPED group-scoped grant, target group not in this run: group={g['name']} "
                                    f"role={x['roleName']} ({x['roleId']}) scoped to {x.get('groupName') or x.get('groupId')!r}")
            elif x.get("organizationId"):
                org[x["roleId"]] = {"roleId": x["roleId"]}
            else:
                warnings.append(f"SKIPPED grant (unsupported scope): group={g['name']} role={x['roleName']} ({x['roleId']})")
        org = list(org.values())
        stats["grants"] += len(acct) + len(org) + len(grp)
        if not execute or not (acct or org or grp):
            continue
        try:
            for kind, batch in (("acct", acct), ("grp", grp)):
                for i in range(0, len(batch), CHUNK):
                    part = batch[i:i + CHUNK]
                    nrgql.grant(client, t["id"], **{"account_grants" if kind == "acct" else "group_grants": part})
                    LOG.debug("granted %d %s grants on group %r", len(part), kind, g["name"])
                    if manifest:
                        manifest.add(op="grant", groupId=t["id"], **{kind: part})
            if org:
                nrgql.grant(client, t["id"], org_grants=org)
                LOG.debug("granted %d organization grants on group %r", len(org), g["name"])
                if manifest:
                    manifest.add(op="grant", groupId=t["id"], org=org)
            fails.ok()
        except nrgql.NerdGraphError as e:
            fails.add(f"grants for group {g['name']}: {e}")
            for m in g["members"]:
                if not only_users or m in only_users:
                    errors.setdefault(m, f"grants for group {g['name']} failed: {e}"[:300])

    # 3. users and memberships (skipped when the target is SCIM-managed)
    if not with_users:
        return
    needed = {m for g in src_groups for m in g["members"] if not only_users or m in only_users}
    to_create = []
    for u in src["users"]:
        if u["email"] in tgt_users or ((only_groups or only_users) and u["email"] not in needed):
            continue
        if not u.get("tier"):
            errors[u["email"]] = f"unsupported user type {u.get('typeName')!r}"
            warnings.append(f"SKIPPED user {u['email']}: unsupported user type {u.get('typeName')!r}")
            continue
        to_create.append(u)
    LOG.info("Users: %d to create, %d already in the target", len(to_create), len(needed & set(tgt_users)))
    prog = Progress("users created", len(to_create))
    for u in to_create:
        stats["users"] += 1
        if not execute:
            tgt_users[u["email"]] = f"dry:{u['email']}"
            continue
        try:
            uid = nrgql.create_user(client, domain_id, u["email"], u["name"], u["tier"])
            fails.ok()
        except nrgql.NerdGraphError as e:
            uid = _recover_user(client, domain_id, u["email"]) if nrgql.OUTCOME_UNKNOWN in str(e) else None
            if uid:
                LOG.warning("User %s was created although the call reported an error; recorded it", u["email"])
            else:
                stats["users"] -= 1
                errors[u["email"]] = f"user creation failed: {e}"[:300]
                fails.add(f"user {u['email']}: {e}")
                prog.tick()
                continue
        tgt_users[u["email"]] = uid
        LOG.debug("created user %s -> %s", u["email"], uid)
        if manifest:
            manifest.add(op="user", id=uid, email=u["email"])
        prog.tick()

    plans = []
    for g in src_groups:
        if g["name"] in broken_groups or g["name"] not in tgt_groups:
            continue
        t = tgt_groups[g["name"]]
        emails = [m for m in g["members"]
                  if m not in t["members"] and m in tgt_users and (not only_users or m in only_users)]
        plans.append((g, t, emails))
        stats["memberships"] += len(emails)
    prog = Progress("membership batches", sum(math.ceil(len(e) / CHUNK) for _, _, e in plans))
    for g, t, emails in plans:
        if not execute:
            continue
        for i in range(0, len(emails), CHUNK):
            part = emails[i:i + CHUNK]
            try:
                nrgql.add_members(client, t["id"], [tgt_users[m] for m in part])
                LOG.debug("added %d members to group %r", len(part), g["name"])
                if manifest:
                    manifest.add(op="member", groupId=t["id"], userIds=[tgt_users[m] for m in part])
                fails.ok()
            except nrgql.NerdGraphError as e:
                fails.add(f"members of {g['name']}: {e}")
                for m in part:
                    errors[m] = f"membership in {g['name']} failed: {e}"[:300]
            prog.tick()


# ---------------------------------------------------------------- rollback

def rollback(client, domain_id, manifest_path, execute, max_consecutive_failures=10):
    """Undo, newest first, only what the manifest says `apply` created. Pre-existing target objects are never touched."""
    mdomain, events = load_manifest(manifest_path)
    if mdomain != domain_id:
        sys.exit(f"Manifest was written for domain {mdomain}, not {domain_id}; refusing.")
    if execute:
        problems = nrgql.check_rollback_schema(client)
        if problems:
            sys.exit("Cannot roll back, API does not match:\n  " + "\n  ".join(problems))
    stats = dict(grants=0, memberships=0, users=0, groups=0)
    fails = Failures(max_consecutive_failures)
    done = open(manifest_path, "a") if execute else None
    prog = Progress("rollback steps", len(events))
    try:
        for i, e in reversed(events):
            op = e["op"]
            kind = {"grant": "grants", "member": "memberships", "user": "users", "group": "groups"}[op]
            try:
                if execute:
                    if op == "grant":
                        nrgql.revoke(client, e["groupId"], e.get("acct"), e.get("org"), e.get("grp"))
                    elif op == "member":
                        nrgql.remove_members(client, e["groupId"], e["userIds"])
                    elif op == "user":
                        nrgql.delete_user(client, e["id"])
                    else:
                        nrgql.delete_group(client, e["id"])
                    done.write(json.dumps({"undone": i}) + "\n")
                    done.flush()
                    LOG.debug("undone %s %s", op, e.get("email") or e.get("name") or e.get("id") or e["groupId"])
                    fails.ok()
                stats[kind] += (len(e.get("acct") or []) + len(e.get("org") or []) + len(e.get("grp") or [])
                                if op == "grant" else len(e["userIds"]) if op == "member" else 1)
            except nrgql.NerdGraphError as ex:
                fails.add(f"{op} {e.get('email') or e.get('name') or e.get('id') or e['groupId']}: {ex}")
            prog.tick()
    except AbortRun as ex:
        LOG.error("%s", ex)
        stats["aborted"] = True
    return stats, fails.items


def rollback_users(client, domain_id, manifest_path, emails, execute, max_consecutive_failures=10):
    """Remove only the given users, and only if this manifest shows the tool created them. Groups and grants stay.
    Returns (stats, failures, not_created_by_tool)."""
    mdomain, events = load_manifest(manifest_path)
    if mdomain != domain_id:
        sys.exit(f"Manifest was written for domain {mdomain}, not {domain_id}; refusing.")
    created = {e["email"].lower(): e["id"] for _, e in events if e["op"] == "user"}
    chosen = {e: created[e] for e in emails if e in created}
    skipped = sorted(set(emails) - set(chosen))
    if execute and chosen:
        problems = nrgql.check_rollback_schema(client)
        if problems:
            sys.exit("Cannot roll back, API does not match:\n  " + "\n  ".join(problems))
    id_to_email = {v: k for k, v in chosen.items()}
    groups_of = {}
    for _, e in events:
        if e["op"] == "member":
            for uid in e["userIds"]:
                if uid in id_to_email:
                    groups_of.setdefault(uid, set()).add(e["groupId"])
    stats = dict(users=0, memberships=0)
    fails = Failures(max_consecutive_failures)
    done = open(manifest_path, "a") if execute else None
    prog = Progress("users removed", len(chosen))
    try:
        for email, uid in sorted(chosen.items()):
            try:
                if execute:
                    for gid in sorted(groups_of.get(uid, ())):
                        nrgql.remove_members(client, gid, [uid])
                    nrgql.delete_user(client, uid)
                    done.write(json.dumps({"undone_user": uid}) + "\n")
                    done.flush()
                    LOG.debug("removed user %s (%s)", email, uid)
                    fails.ok()
                stats["memberships"] += len(groups_of.get(uid, ()))
                stats["users"] += 1
            except nrgql.NerdGraphError as ex:
                fails.add(f"user {email}: {ex}")
            prog.tick()
    except AbortRun as ex:
        LOG.error("%s", ex)
        stats["aborted"] = True
    return stats, fails.items, skipped


# ---------------------------------------------------------------- verify

def verify(client, domain_id, src, with_users, exclude_roles, only_users=frozenset(),
           skip_empty_groups=False, skip_no_access=False):
    src = drop_groups(src, skip_empty_groups, skip_no_access)
    skip_roles = {r.lower() for r in exclude_roles}
    tgt_users, tgt_groups = snapshot_target(client, domain_id)
    problems = []
    if with_users:
        missing = [u["email"] for u in src["users"]
                   if u["email"] not in tgt_users and (not only_users or u["email"] in only_users)]
        if missing:
            problems.append(f"{len(missing)} users missing (e.g. {missing[:3]})")
    for g in src["groups"]:
        if only_users and not only_users & set(g["members"]):
            continue
        t = tgt_groups.get(g["name"])
        if not t:
            problems.append(f"group missing: {g['name']}")
            continue
        miss_g = [x for x in g["grants"]
                  if (x["roleName"] or "").lower() not in skip_roles and grant_key(x) not in t["grants"]]
        if miss_g:
            problems.append(f"{g['name']}: {len(miss_g)} grants missing")
        expected = set(g["members"]) & only_users if only_users else set(g["members"])
        if with_users and expected - t["members"]:
            problems.append(f"{g['name']}: {len(expected - t['members'])} members missing")
    return problems


# ---------------------------------------------------------------- worksheet

def selected_users(a, src):
    """Emails chosen by --user and/or the worksheet's migrate=yes rows. Empty set means no user filter."""
    only = {u.lower() for u in a.user}
    if a.users_csv:
        choices, errors = userlist.read_choices(a.users_csv)
        if errors:
            sys.exit("Fix the worksheet first:\n  " + "\n  ".join(errors))
        known = {u["email"] for u in src["users"]}
        for e in sorted(set(choices) - known):
            say(f"WARNING {e} is in the worksheet but not in the export; ignored")
        only |= {e for e, v in choices.items() if v == "yes" and e in known}
        if not only:
            sys.exit("No users are marked migrate=yes in the worksheet; nothing to do.")
        say(f"Worksheet selects {len(only)} users")
    return only


def write_worksheet(client, target_domain, src, path, default, errors=None):
    """Write users.csv, keeping any migrate choices already in the file and refreshing the status columns."""
    choices = {}
    if os.path.exists(path):
        choices, problems = userlist.read_choices(path)
        if problems:
            sys.exit(f"{path} has invalid rows; fix or move it first:\n  " + "\n  ".join(problems))
        say(f"Keeping the migrate choices already in {path}")
    target = {email_of(u) for u in nrgql.read_users(client, target_domain)}
    tgt_groups = {g["displayName"]: {email_of(m) for m in nrgql.read_members(client, target_domain, g["id"])}
                  for g in nrgql.read_groups(client, target_domain)}
    rows = userlist.build_rows(src, target, choices, default, tgt_groups, errors, time.strftime("%Y-%m-%d %H:%M:%S"))
    userlist.write_csv(path, rows)
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    say(f"Updated {path}: {len(rows)} users. " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))


def refresh_worksheet(client, target_domain, src_path, csv_path, errors=None):
    """Called after every real run so users.csv always shows the current state. Never fails the run."""
    if not (csv_path and os.path.exists(csv_path) and os.path.exists(src_path)):
        return
    try:
        write_worksheet(client, target_domain, load_export(src_path), csv_path, "no", errors)
    except (nrgql.NerdGraphError, SystemExit, OSError) as e:
        LOG.warning("Could not update %s: %s (close it if it is open in a spreadsheet, then run users-csv)", csv_path, e)


# ---------------------------------------------------------------- cli

def estimate(stats):
    """Lower bound on write calls for a dry run, to help plan a large run."""
    n = stats["groups"] + stats["users"] + math.ceil(stats["grants"] / CHUNK) + math.ceil(stats["memberships"] / CHUNK)
    return f"at least {n} write calls"


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--region", choices=["US", "EU"], default=None)
    p.add_argument("--log-dir", default="out/logs", help="where run logs are written (default out/logs)")
    p.add_argument("--throttle-ms", type=int, default=0, help="pause after every write call, to stay under rate limits")
    p.add_argument("--max-failures", type=int, default=10,
                   help="stop after this many failures in a row (0 = never stop); default 10")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("domains")
    s = sub.add_parser("preflight", help="check the API key, both domains and API support; writes nothing")
    s.add_argument("--source", required=True, help="current (source) authentication domain ID")
    s.add_argument("--target", required=True, help="new (target) authentication domain ID")
    s = sub.add_parser("prepare", help="export the source domain and generate the users.csv worksheet")
    s.add_argument("--source", required=True, help="current (source) authentication domain ID")
    s.add_argument("--target", required=True, help="new (target) authentication domain ID")
    s.add_argument("--out-dir", default="out")
    s.add_argument("--default", choices=["yes", "no"], default="no", help="initial value of the migrate column")
    s = sub.add_parser("users-csv", help="refresh users.csv from an export; keeps existing migrate choices")
    s.add_argument("--domain", required=True, help="target domain ID")
    s.add_argument("--in", dest="inp", default="out/source.json")
    s.add_argument("--out", default="out/users.csv")
    s.add_argument("--default", choices=["yes", "no"], default="no")
    for name in ("export", "apply", "verify", "rollback"):
        s = sub.add_parser(name)
        s.add_argument("--domain", required=True, help="source domain ID for export, target for apply/verify/rollback")
        if name == "export":
            s.add_argument("--out", default="out/source.json")
        elif name == "rollback":
            s.add_argument("--manifest", required=True, help="manifest written by `apply --execute`")
            s.add_argument("--in", dest="inp", default="out/source.json", help="export, used to refresh the worksheet")
            s.add_argument("--users-csv", default=None, help="selective rollback: remove only the users marked migrate=no in this "
                           "worksheet (and created by the manifest). Without --user/--users-csv, the whole manifest is undone")
            s.add_argument("--user", action="append", default=[], help="selective rollback of these user emails (repeatable)")
            s.add_argument("--execute", action="store_true", help="perform deletes; default is a dry run")
            s.add_argument("--yes", action="store_true", help="do not ask to type the domain name (for scripts)")
        else:
            s.add_argument("--in", dest="inp", default="out/source.json")
            s.add_argument("--no-users", action="store_true", help="groups and grants only (target will be SCIM-managed)")
            s.add_argument("--exclude-role", action="append", default=[], help="role display name to leave out (repeatable)")
            s.add_argument("--skip-empty-groups", action="store_true", help="leave out groups that have no members")
            s.add_argument("--skip-no-access", action="store_true", help="leave out groups that have no role grants")
            s.add_argument("--user", action="append", default=[], help="limit to these user emails (single-user test)")
            s.add_argument("--users-csv", default=None, help="only users marked migrate=yes in this worksheet (plus any --user)")
        if name == "apply":
            s.add_argument("--group", action="append", default=[], help="limit to these group names (pilot runs)")
            s.add_argument("--execute", action="store_true", help="perform writes; default is a dry run")
            s.add_argument("--yes", action="store_true", help="do not ask to type the domain name (for scripts)")
            s.add_argument("--allow-users-in-scim", action="store_true",
                           help="create users even though the target is SCIM-managed (normally use --no-users)")
            s.add_argument("--manifest", default=None, help="where to record created objects (default out/manifest-<time>.jsonl)")
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    log_path = setup_logging(a.cmd, a.log_dir)
    LOG.debug("tool version %s, python %s, argv: %s", __version__, sys.version.split()[0], sys.argv[1:])
    LOG.info("Log file: %s", log_path)

    try:
        client = nrgql.Client(region=a.region, pause_ms=a.throttle_ms)
        code = run(a, client)
    except KeyboardInterrupt:
        LOG.error("Interrupted. Finished work is kept; run the same command again to continue.")
        code = 130
    except nrgql.NerdGraphError as e:
        LOG.error("API error: %s", e)
        code = 1
    LOG.info("Finished with exit code %s. Full log: %s", code, log_path)
    sys.exit(code)


def run(a, client):
    if a.cmd == "domains":
        for d in nrgql.list_domains(client):
            say(f"{d['id']}  {d['name']}  ({d['provisioningType']})")
    elif a.cmd == "preflight":
        bad = preflight(client, a.source, a.target)
        say("Preflight failed: fix the FAIL lines above." if bad else "Preflight OK.")
        return 1 if bad else 0
    elif a.cmd == "prepare":
        if a.source == a.target:
            sys.exit("Source and target domains are the same; refusing.")
        data = export(client, a.source)
        src_path = os.path.join(a.out_dir, "source.json")
        write_json_atomic(src_path, data)
        say(f"Wrote {src_path}: {len(data['users'])} users, {len(data['groups'])} groups, "
            f"{sum(len(g['grants']) for g in data['groups'])} grants")
        write_worksheet(client, a.target, data, os.path.join(a.out_dir, "users.csv"), a.default)
    elif a.cmd == "users-csv":
        src = load_export(a.inp)
        if a.domain == src["domain"]["id"]:
            sys.exit("Target domain equals the source domain in the export; refusing.")
        write_worksheet(client, a.domain, src, a.out, a.default)
    elif a.cmd == "export":
        data = export(client, a.domain)
        write_json_atomic(a.out, data)
        say(f"Wrote {a.out}: {len(data['users'])} users, {len(data['groups'])} groups, "
            f"{sum(len(g['grants']) for g in data['groups'])} grants")
    elif a.cmd == "rollback":
        if a.execute:
            confirm_execute(client, a.domain, "DELETE what the manifest created", a.yes)
        csv_path = a.users_csv or os.path.join(os.path.dirname(a.inp), "users.csv")
        if a.users_csv or a.user:
            wanted = {u.lower() for u in a.user}
            if a.users_csv:
                choices, errors = userlist.read_choices(a.users_csv)
                if errors:
                    sys.exit("Fix the worksheet first:\n  " + "\n  ".join(errors))
                wanted |= {e for e, v in choices.items() if v == "no"}
            if not wanted:
                sys.exit("No users selected: nobody is marked migrate=no and no --user was given.")
            stats, failures, skipped = rollback_users(client, a.domain, a.manifest, wanted, a.execute, a.max_failures)
            say(("REMOVED" if a.execute else "DRY RUN (nothing deleted), would remove") + f": {stats}")
            if skipped:
                say(f"Left alone: {len(skipped)} marked users were not created by this manifest (or already removed).")
        else:
            stats, failures = rollback(client, a.domain, a.manifest, a.execute, a.max_failures)
            say(("ROLLED BACK" if a.execute else "DRY RUN (nothing deleted)") + f": {stats}")
        if a.execute:
            refresh_worksheet(client, a.domain, a.inp, csv_path)
        for f in failures:
            say(f"FAILED {f}")
        return 1 if failures or stats.get("aborted") else 0
    else:
        src = load_export(a.inp)
        if a.domain == src["domain"]["id"]:
            sys.exit("Target domain equals the source domain in the export; refusing.")
        only_users = selected_users(a, src)
        if a.cmd == "apply":
            manifest, errors = None, {}
            csv_path = a.users_csv or os.path.join(os.path.dirname(a.inp), "users.csv")
            tgt = find_domain(client, a.domain, "Target")
            if is_scim(tgt) and not a.no_users and not a.allow_users_in_scim:
                msg = (f"Target {tgt['name']} is SCIM-managed; its users should come from SCIM. "
                       f"Use --no-users, or --allow-users-in-scim to create users anyway.")
                if a.execute:
                    sys.exit(msg)
                say(f"WARNING {msg}")
            if a.execute:
                confirm_execute(client, a.domain, "WRITE users, groups and grants", a.yes, src["domain"].get("name"))
                path = a.manifest or time.strftime("out/manifest-%Y%m%d-%H%M%S.jsonl")
                manifest = Manifest(path, a.domain)
                say(f"Recording created objects in {path}")
            try:
                stats, failures, warnings = apply(client, a.domain, src, a.execute, not a.no_users, a.exclude_role,
                                                  set(a.group), only_users, manifest, errors, a.max_failures,
                                                  a.skip_empty_groups, a.skip_no_access)
            except KeyboardInterrupt:
                if a.execute:
                    refresh_worksheet(client, a.domain, a.inp, csv_path, errors)
                raise
            say(("EXECUTED" if a.execute else "DRY RUN (nothing written)") + f": {stats}")
            if not a.execute:
                say("Estimated size: " + estimate(stats))
            for w in warnings:
                say(f"WARNING {w}")
            for f in failures:
                say(f"FAILED {f}")
            if a.execute:
                refresh_worksheet(client, a.domain, a.inp, csv_path, errors)
            return 1 if failures or stats.get("aborted") else 0
        problems = verify(client, a.domain, src, not a.no_users, a.exclude_role, only_users,
                          a.skip_empty_groups, a.skip_no_access)
        say("\n".join(problems) or "OK: target matches export")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    main()
