"""Minimal NerdGraph client (stdlib only) plus read/write helpers for an authentication domain."""
import json
import logging
import os
import random
import re
import time
import urllib.error
import urllib.request

ENDPOINTS = {
    "US": "https://api.newrelic.com/graphql",
    "EU": "https://api.eu.newrelic.com/graphql",
}
LOG = logging.getLogger("migrator.api")
OUTCOME_UNKNOWN = "outcome unknown"


class NerdGraphError(Exception):
    pass


def _label(gql):
    m = re.search(r"\b(userManagement\w*|authorizationManagement\w*)\b", gql)
    return ("write " if gql.lstrip().startswith("mutation") else "read ") + (m.group(1) if m else "query")


class Client:
    """Reads are retried on timeouts, 429 and 5xx. Writes are retried only on 429 (rejected, never processed): after a
    timeout or 5xx a write may or may not have happened, so it is reported as 'outcome unknown' instead of repeated."""

    def __init__(self, api_key=None, region=None, retries=5, pause_ms=0):
        self.api_key = api_key or os.environ.get("NEW_RELIC_API_KEY")
        if not self.api_key:
            raise NerdGraphError("Set NEW_RELIC_API_KEY (a User API key with admin access).")
        self.url = ENDPOINTS[(region or os.environ.get("NEW_RELIC_REGION", "US")).upper()]
        self.retries = retries
        self.pause = pause_ms / 1000.0

    @staticmethod
    def _backoff(attempt, retry_after=None):
        if retry_after and retry_after.isdigit():
            return min(int(retry_after), 120)
        return min(60, 2 ** attempt) + random.random()

    def query(self, gql, variables=None):
        is_write = gql.lstrip().startswith("mutation")
        label = _label(gql)
        body = json.dumps({"query": gql, "variables": variables or {}}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json", "API-Key": self.api_key},
        )
        for attempt in range(self.retries + 1):
            t0 = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    payload = json.load(resp)
                LOG.debug("%s ok %dms attempt=%d", label, (time.monotonic() - t0) * 1000, attempt + 1)
                break
            except urllib.error.HTTPError as e:
                retryable = e.code == 429 or (not is_write and e.code in (500, 502, 503, 504))
                if retryable and attempt < self.retries:
                    wait = self._backoff(attempt, e.headers.get("Retry-After") if e.headers else None)
                    LOG.warning("%s HTTP %s, retrying in %.0fs (attempt %d)", label, e.code, wait, attempt + 1)
                    time.sleep(wait)
                    continue
                unsure = f" ({OUTCOME_UNKNOWN}; check the target before re-running)" if is_write and e.code >= 500 else ""
                raise NerdGraphError(f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}{unsure}")
            except OSError as e:  # URLError, timeouts, resets
                if not is_write and attempt < self.retries:
                    wait = self._backoff(attempt)
                    LOG.warning("%s %s, retrying in %.0fs (attempt %d)", label, e, wait, attempt + 1)
                    time.sleep(wait)
                    continue
                unsure = f" ({OUTCOME_UNKNOWN}; check the target before re-running)" if is_write else ""
                raise NerdGraphError(f"{e}{unsure}")
        if payload.get("errors"):
            LOG.debug("%s returned errors", label)
            raise NerdGraphError(json.dumps(payload["errors"])[:1500])
        if is_write and self.pause:
            time.sleep(self.pause)
        return payload["data"]


# ---------------------------------------------------------------- reads

Q_DOMAINS = """
query($cursor: String) { actor { organization { userManagement {
  authenticationDomains(cursor: $cursor) { nextCursor authenticationDomains { id name provisioningType } }
} } } }"""

Q_USERS = """
query($domainId: [ID!], $cursor: String) { actor { organization { userManagement {
  authenticationDomains(id: $domainId) { authenticationDomains { users(cursor: $cursor) {
    nextCursor users { id email name type { id displayName } }
  } } }
} } } }"""

Q_GROUPS = """
query($domainId: [ID!], $cursor: String) { actor { organization { userManagement {
  authenticationDomains(id: $domainId) { authenticationDomains { groups(cursor: $cursor) {
    nextCursor groups { id displayName }
  } } }
} } } }"""

Q_MEMBERS = """
query($domainId: [ID!], $groupId: [ID!], $cursor: String) { actor { organization { userManagement {
  authenticationDomains(id: $domainId) { authenticationDomains { groups(id: $groupId) { groups {
    users(cursor: $cursor) { nextCursor users { id email } }
  } } } }
} } } }"""

Q_GRANTS = """
query($domainId: [ID!], $groupId: [ID!], $cursor: String) { actor { organization { authorizationManagement {
  authenticationDomains(id: $domainId) { authenticationDomains { groups(id: $groupId) { groups {
    roles(cursor: $cursor) { nextCursor roles { roleId displayName name type accountId organizationId groupId dataAccessPolicyId } }
  } } } }
} } } }"""


def _domain_node(data, section):
    return data["actor"]["organization"][section]["authenticationDomains"]["authenticationDomains"][0]


def list_domains(client):
    out, cursor, seen = [], None, set()
    while True:
        d = client.query(Q_DOMAINS, {"cursor": cursor})["actor"]["organization"]["userManagement"]["authenticationDomains"]
        out += d["authenticationDomains"]
        cursor = d["nextCursor"]
        if not cursor:
            return out
        if cursor in seen:
            raise NerdGraphError("pagination did not advance (repeated cursor)")
        seen.add(cursor)


def _paged(client, gql, variables, section, path):
    """Follow nextCursor; `path` picks the paged connection out of the domain/group node."""
    items, cursor, seen = [], None, set()
    while True:
        node = _domain_node(client.query(gql, {**variables, "cursor": cursor}), section)
        conn = path(node)
        key = next(k for k in conn if k != "nextCursor")
        items += conn[key]
        cursor = conn["nextCursor"]
        if not cursor:
            return items
        if cursor in seen:
            raise NerdGraphError("pagination did not advance (repeated cursor)")
        seen.add(cursor)


def read_users(client, domain_id):
    return _paged(client, Q_USERS, {"domainId": [domain_id]}, "userManagement", lambda n: n["users"])


def read_groups(client, domain_id):
    return _paged(client, Q_GROUPS, {"domainId": [domain_id]}, "userManagement", lambda n: n["groups"])


def read_members(client, domain_id, group_id):
    return _paged(client, Q_MEMBERS, {"domainId": [domain_id], "groupId": [group_id]},
                  "userManagement", lambda n: n["groups"]["groups"][0]["users"])


def read_grants(client, domain_id, group_id):
    return _paged(client, Q_GRANTS, {"domainId": [domain_id], "groupId": [group_id]},
                  "authorizationManagement", lambda n: n["groups"]["groups"][0]["roles"])


# ---------------------------------------------------------------- writes

M_CREATE_GROUP = """
mutation($domainId: ID!, $name: String!) { userManagementCreateGroup(
  createGroupOptions: {authenticationDomainId: $domainId, displayName: $name}) { group { id displayName } } }"""

M_CREATE_USER = """
mutation($domainId: ID!, $email: String!, $name: String!, $tier: UserManagementRequestedTierName!) {
  userManagementCreateUser(createUserOptions: {authenticationDomainId: $domainId, email: $email,
    name: $name, userType: $tier}) { createdUser { id email } } }"""

M_ADD_MEMBERS = """
mutation($groupIds: [ID!]!, $userIds: [ID!]!) { userManagementAddUsersToGroups(
  addUsersToGroupsOptions: {groupIds: $groupIds, userIds: $userIds}) { groups { id } } }"""

M_GRANT = """
mutation($groupId: ID!, $acct: [AuthorizationManagementAccountAccessGrant!],
    $org: [AuthorizationManagementOrganizationAccessGrant!], $grp: [AuthorizationManagementGroupAccessGrant!]) {
  authorizationManagementGrantAccess(grantAccessOptions: {groupId: $groupId,
    accountAccessGrants: $acct, organizationAccessGrants: $org, groupAccessGrants: $grp}) { roles { roleId } } }"""


def create_group(client, domain_id, name):
    r = client.query(M_CREATE_GROUP, {"domainId": domain_id, "name": name})
    return r["userManagementCreateGroup"]["group"]["id"]


def create_user(client, domain_id, email, name, tier):
    r = client.query(M_CREATE_USER, {"domainId": domain_id, "email": email, "name": name, "tier": tier})
    return r["userManagementCreateUser"]["createdUser"]["id"]


def add_members(client, group_id, user_ids):
    client.query(M_ADD_MEMBERS, {"groupIds": [group_id], "userIds": user_ids})


def grant(client, group_id, account_grants=None, org_grants=None, group_grants=None):
    client.query(M_GRANT, {"groupId": group_id, "acct": account_grants or None,
                           "org": org_grants or None, "grp": group_grants or None})


# ---------------------------------------------------------------- rollback (only used on objects this tool created)

M_DELETE_GROUP = "mutation($id: String!) { userManagementDeleteGroup(groupOptions: {id: $id}) { group { id } } }"
M_DELETE_USER = "mutation($id: ID!) { userManagementDeleteUser(deleteUserOptions: {id: $id}) { deletedUser { id } } }"
M_REMOVE_MEMBERS = """
mutation($groupIds: [ID!]!, $userIds: [ID!]!) { userManagementRemoveUsersFromGroups(
  removeUsersFromGroupsOptions: {groupIds: $groupIds, userIds: $userIds}) { groups { id } } }"""
M_REVOKE = """
mutation($groupId: ID!, $acct: [AuthorizationManagementAccountAccessGrant!],
    $org: [AuthorizationManagementOrganizationAccessGrant!], $grp: [AuthorizationManagementGroupAccessGrant!]) {
  authorizationManagementRevokeAccess(revokeAccessOptions: {groupId: $groupId,
    accountAccessGrants: $acct, organizationAccessGrants: $org, groupAccessGrants: $grp}) { roles { roleId } } }"""

ROLLBACK_MUTATIONS = {
    "userManagementDeleteGroup": "groupOptions",
    "userManagementDeleteUser": "deleteUserOptions",
    "userManagementRemoveUsersFromGroups": "removeUsersFromGroupsOptions",
    "authorizationManagementRevokeAccess": "revokeAccessOptions",
}


def check_rollback_schema(client):
    """Return a list of problems if the API lacks the mutations/arguments rollback relies on."""
    fields = client.query("{ __schema { mutationType { fields { name args { name } } } } }")["__schema"]["mutationType"]["fields"]
    have = {f["name"]: {a["name"] for a in f["args"]} for f in fields}
    return [f"{m}({arg}) not found in this NerdGraph schema" for m, arg in ROLLBACK_MUTATIONS.items()
            if arg not in have.get(m, set())]


def delete_group(client, group_id):
    client.query(M_DELETE_GROUP, {"id": group_id})


def delete_user(client, user_id):
    client.query(M_DELETE_USER, {"id": user_id})


def remove_members(client, group_id, user_ids):
    client.query(M_REMOVE_MEMBERS, {"groupIds": [group_id], "userIds": user_ids})


def revoke(client, group_id, account_grants=None, org_grants=None, group_grants=None):
    client.query(M_REVOKE, {"groupId": group_id, "acct": account_grants or None,
                            "org": org_grants or None, "grp": group_grants or None})
