from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from standstill import state as _state


@dataclass
class Account:
    id: str
    arn: str
    name: str
    email: str
    status: str
    ou_id: str
    ou_name: str


@dataclass
class OUNode:
    id: str
    arn: str
    name: str
    parent_id: Optional[str]
    children: list[OUNode] = field(default_factory=list)
    accounts: list[Account] = field(default_factory=list)

    @property
    def account_count(self) -> int:
        return len(self.accounts) + sum(c.account_count for c in self.children)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _list_ous(client, parent_id: str) -> list[dict]:
    items: list[dict] = []
    kwargs: dict = {"ParentId": parent_id}
    while True:
        resp = client.list_organizational_units_for_parent(**kwargs)
        items.extend(resp.get("OrganizationalUnits", []))
        if "NextToken" not in resp:
            break
        kwargs["NextToken"] = resp["NextToken"]
    return items


def _list_accounts(client, parent_id: str) -> list[dict]:
    items: list[dict] = []
    kwargs: dict = {"ParentId": parent_id}
    while True:
        resp = client.list_accounts_for_parent(**kwargs)
        items.extend(resp.get("Accounts", []))
        if "NextToken" not in resp:
            break
        kwargs["NextToken"] = resp["NextToken"]
    return items


def _build_node(client, raw_ou: dict, parent_id: Optional[str]) -> OUNode:
    node = OUNode(
        id=raw_ou["Id"],
        arn=raw_ou["Arn"],
        name=raw_ou["Name"],
        parent_id=parent_id,
    )
    for raw_acct in _list_accounts(client, raw_ou["Id"]):
        node.accounts.append(
            Account(
                id=raw_acct["Id"],
                arn=raw_acct["Arn"],
                name=raw_acct["Name"],
                email=raw_acct.get("Email", ""),
                status=raw_acct.get("Status", "UNKNOWN"),
                ou_id=raw_ou["Id"],
                ou_name=raw_ou["Name"],
            )
        )
    for child_ou in _list_ous(client, raw_ou["Id"]):
        node.children.append(_build_node(client, child_ou, raw_ou["Id"]))
    return node


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_ou_tree() -> list[OUNode]:
    """
    Return the list of top-level OUNodes (direct children of the Org root).
    Recursively populates children and accounts.
    """
    org = _state.state.get_client("organizations")
    roots = org.list_roots().get("Roots", [])
    if not roots:
        raise RuntimeError("No AWS Organizations root found.")
    root_id: str = roots[0]["Id"]

    top_ous = _list_ous(org, root_id)
    return [_build_node(org, ou, root_id) for ou in top_ous]


def flatten_ous(nodes: list[OUNode]) -> list[OUNode]:
    """DFS-flatten the OU tree into a single list."""
    result: list[OUNode] = []
    for node in nodes:
        result.append(node)
        result.extend(flatten_ous(node.children))
    return result


def account_id_to_name_map() -> dict[str, str]:
    """
    Return ``{account_id: account_name}`` for every account in the organization.

    Uses ``organizations:ListAccounts`` directly — cheaper and faster than
    walking the full OU tree when you only need name resolution.
    """
    org = _state.state.get_client("organizations")
    result: dict[str, str] = {}
    kwargs: dict = {}
    while True:
        resp = org.list_accounts(**kwargs)
        for acct in resp.get("Accounts", []):
            result[acct["Id"]] = acct["Name"]
        if "NextToken" not in resp:
            break
        kwargs["NextToken"] = resp["NextToken"]
    return result


def all_accounts(nodes: list[OUNode]) -> list[Account]:
    """Collect every account from the entire tree."""
    accounts: list[Account] = []
    for node in flatten_ous(nodes):
        accounts.extend(node.accounts)
    return accounts
