"""Pydantic request/response models for the normalization API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.anonymize import parse_key_hex
from app.policy import (
    MINIMIZE_POLICY_RULE_LIMIT,
    _MAX_PREFIXLEN,
    parse_address,
    parse_network,
)


class PolicyRequest(BaseModel):
    allow: list[str] = Field(
        default_factory=list,
        description="Allowed CIDR list (IPv4/IPv6 may be mixed).",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Denied CIDR list (IPv4/IPv6 may be mixed).",
    )

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response carrying the offending field and value.
        for value in values:
            parse_network(value)
        return values


class EvaluateRequest(PolicyRequest):
    addresses: list[str] = Field(
        default_factory=list,
        description="Bare IPv4/IPv6 addresses to evaluate, in response order.",
    )

    @field_validator("addresses")
    @classmethod
    def _validate_address_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_address(value)
        return values


class ListStats(BaseModel):
    input: int = Field(description="Raw number of entries in the request list.")
    unique: int = Field(description="Distinct networks after de-duplication.")
    duplicates_removed: int = Field(description="input - unique.")
    ipv4: int = Field(description="Distinct IPv4 networks after de-duplication.")
    ipv6: int = Field(description="Distinct IPv6 networks after de-duplication.")


class OutputStats(BaseModel):
    ipv4: int
    ipv6: int
    total: int


class Stats(BaseModel):
    allow: ListStats
    deny: ListStats
    output: OutputStats


class NormalizeResponse(BaseModel):
    ipv4: list[str] = Field(
        description="allow - deny for IPv4, minimal, non-overlapping, sorted.",
    )
    ipv6: list[str] = Field(
        description="allow - deny for IPv6, minimal, non-overlapping, sorted.",
    )
    stats: Stats


class AddressDecision(BaseModel):
    decision: Literal["allow", "deny", "unmatched"] = Field(
        description=(
            "Winner side after longest-prefix matching; 'unmatched' when no "
            "list entry contains the address."
        ),
    )
    matched_cidr: str | None = Field(
        description="Canonical CIDR of the winning entry; null when unmatched.",
    )
    matched_side: Literal["allow", "deny"] | None = Field(
        description="List the winning entry came from; null when unmatched.",
    )


class CompareRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) limiting the comparison region. "
            "Strict: host bits must be zero."
        ),
    )
    baseline: PolicyRequest = Field(
        default_factory=PolicyRequest,
        description="Baseline allow/deny policy set.",
    )
    candidate: PolicyRequest = Field(
        default_factory=PolicyRequest,
        description="Candidate allow/deny policy set to compare against.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        # A missing/blank scope is invalid; a bare address (host prefix) is
        # accepted, just like allow/deny entries.
        parse_network(value)
        return value


class CompareDifference(BaseModel):
    cidr: str = Field(
        description="Non-overlapping region inside scope where decisions differ.",
    )
    baseline_decision: Literal["allow", "deny", "unmatched"] = Field(
        description="Baseline decision throughout cidr.",
    )
    candidate_decision: Literal["allow", "deny", "unmatched"] = Field(
        description="Candidate decision throughout cidr.",
    )


class CompareResponse(BaseModel):
    differences: list[CompareDifference] = Field(
        description=(
            "Regions whose decision changes, sorted IPv4 then IPv6, by "
            "network address then prefix length."
        ),
    )
    transition_counts: dict[str, str] = Field(
        description=(
            "Addresses covered per 'baseline->candidate' transition type, "
            "as decimal strings; all six transitions are present (0 when "
            "unused)."
        ),
    )


class AuditRulesRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) limiting the audit region. "
            "Strict: host bits must be zero."
        ),
    )
    allow: list[str] = Field(
        default_factory=list,
        description="Allowed CIDR list; every entry must match the scope family.",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Denied CIDR list; every entry must match the scope family.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_family_against_scope(self) -> "AuditRulesRequest":
        # A wrong-family rule is a 422 here (unlike /compare, which ignores
        # it): the audit is explicitly scoped to one address family.
        scope = parse_network(self.scope)
        for side, entries in (("allow", self.allow), ("deny", self.deny)):
            for value in entries:
                network = parse_network(value)
                if not isinstance(network, type(scope)):
                    raise ValueError(
                        f"{side} CIDR {network} does not match the scope "
                        f"address family ({scope})"
                    )
        return self


class RuleReference(BaseModel):
    side: Literal["allow", "deny"] = Field(
        description="Input list the shadowing rule came from.",
    )
    index: int = Field(
        description="Position of the shadowing rule in that list (0-based).",
    )


class RuleAuditResult(BaseModel):
    side: Literal["allow", "deny"] = Field(
        description="Input list this rule came from.",
    )
    index: int = Field(
        description="Position of this rule in its input list (0-based).",
    )
    cidr: str = Field(description="Canonical CIDR of the input rule.")
    status: Literal["effective", "shadowed", "out_of_scope"] = Field(
        description=(
            "'effective' when the rule decides somewhere inside scope; "
            "'shadowed' when other rules beat it everywhere inside scope; "
            "'out_of_scope' when the rule CIDR does not intersect scope."
        ),
    )
    witness: str | None = Field(
        default=None,
        description=(
            "Numerically smallest network address in the region where the "
            "rule wins; present only when status is 'effective'."
        ),
    )
    shadowed_by: list[RuleReference] | None = Field(
        default=None,
        description=(
            "Distinct input rules that win every part of this rule's region "
            "inside scope; present only when status is 'shadowed'."
        ),
    )


class AuditRulesResponse(BaseModel):
    allow: list[RuleAuditResult] = Field(
        description="One result per allow entry, in input order.",
    )
    deny: list[RuleAuditResult] = Field(
        description="One result per deny entry, in input order.",
    )


class MinimizePolicyRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) limiting the minimization region. "
            "Strict: host bits must be zero."
        ),
    )
    allow: list[str] = Field(
        default_factory=list,
        description=(
            "Allowed CIDR list; every entry must match the scope family."
        ),
    )
    deny: list[str] = Field(
        default_factory=list,
        description=(
            "Denied CIDR list; every entry must match the scope family."
        ),
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_rules_against_scope(self) -> "MinimizePolicyRequest":
        # Same hard rules as /audit-rules: one family, bounded rule count.
        scope = parse_network(self.scope)
        total = len(self.allow) + len(self.deny)
        if total > MINIMIZE_POLICY_RULE_LIMIT:
            raise ValueError(
                f"total number of allow/deny rules ({total}) exceeds the "
                f"limit of {MINIMIZE_POLICY_RULE_LIMIT}"
            )
        for side, entries in (("allow", self.allow), ("deny", self.deny)):
            for value in entries:
                network = parse_network(value)
                if not isinstance(network, type(scope)):
                    raise ValueError(
                        f"{side} CIDR {network} does not match the scope "
                        f"address family ({scope})"
                    )
        return self


class RetainedRule(RuleReference):
    cidr: str = Field(description="Canonical CIDR of the retained rule.")
    witness: str = Field(
        description=(
            "Numerically smallest IP address at which this rule wins under "
            "the minimized policy inside the scope."
        ),
    )


class RemovedRule(RuleReference):
    cidr: str = Field(description="Canonical CIDR of the removed rule.")


class MinimizePolicyResponse(BaseModel):
    retained: list[RetainedRule] = Field(
        description=(
            "Rules kept in the unique minimum subset. References follow the "
            "original input order: all allow entries (by index) first, then "
            "all deny entries (by index)."
        ),
    )
    removed: list[RemovedRule] = Field(
        description=(
            "Rules dropped by the minimization, in the same original input "
            "order as retained: allow references by index, then deny by index."
        ),
    )


class AllocationRequest(BaseModel):
    id: str = Field(
        min_length=1,
        description="Caller-chosen request identifier; must be unique.",
    )
    prefix_length: int = Field(
        ge=0,
        description=(
            "Requested subnet prefix length; must fit the scope address "
            "family (0-32 for IPv4, 0-128 for IPv6)."
        ),
    )


class AllocateRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) the allocations are carved from. "
            "Strict: host bits must be zero."
        ),
    )
    occupied: list[str] = Field(
        default_factory=list,
        description=(
            "Already-allocated CIDRs. Each must share the scope address "
            "family, lie inside the scope, and not overlap any other entry."
        ),
    )
    requests: list[AllocationRequest] = Field(
        default_factory=list,
        description="Subnet requests, allocated in this order.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("occupied")
    @classmethod
    def _validate_occupied_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_against_scope(self) -> "AllocateRequest":
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response, exactly like the per-field validators above.
        scope = parse_network(self.scope)
        max_prefixlen = _MAX_PREFIXLEN[type(scope)]

        networks = [parse_network(value) for value in self.occupied]
        for network in networks:
            if not isinstance(network, type(scope)):
                raise ValueError(
                    f"occupied CIDR {network} does not match the scope "
                    f"address family ({scope})"
                )
            if not network.subnet_of(scope):
                raise ValueError(
                    f"occupied CIDR {network} is not contained in scope "
                    f"{scope}"
                )
        ordered = sorted(
            networks, key=lambda n: (int(n.network_address), n.prefixlen)
        )
        # For intervals sorted by start, any overlap implies an overlap of
        # some consecutive pair.
        for left, right in zip(ordered, ordered[1:]):
            if left.overlaps(right):
                raise ValueError(
                    f"occupied CIDRs {left} and {right} overlap"
                )

        seen: set[str] = set()
        for item in self.requests:
            if item.id in seen:
                raise ValueError(f"duplicate request id {item.id!r}")
            seen.add(item.id)
            if item.prefix_length > max_prefixlen:
                raise ValueError(
                    f"prefix_length {item.prefix_length} exceeds "
                    f"/{max_prefixlen} for the scope address family"
                )
        return self


class Allocation(BaseModel):
    id: str = Field(description="Identifier of the fulfilled request.")
    cidr: str = Field(
        description="Allocated subnet, canonical CIDR, inside the scope.",
    )


class AllocateResponse(BaseModel):
    allocations: list[Allocation] = Field(
        description=(
            "One entry per request, in request order; the sequence of "
            "network addresses is the lexicographically smallest complete "
            "feasible assignment."
        ),
    )
    remaining: list[str] = Field(
        description=(
            "Free space left in the scope after allocation: minimal, "
            "non-overlapping CIDR set, sorted by network address."
        ),
    )
    remaining_addresses: str = Field(
        description=(
            "Total free addresses left in the scope, as a decimal string "
            "(IPv6 remainders exceed JSON's safe integer range)."
        ),
    )


class AnonymizeRequest(BaseModel):
    key_hex: str = Field(
        description=(
            "HMAC-SHA256 key as exactly 64 hexadecimal characters "
            "(32 bytes / 256 bits); the mapping is stable per key."
        ),
    )
    addresses: list[str] = Field(
        default_factory=list,
        description=(
            "Bare IPv4/IPv6 addresses to anonymize; CIDR notation is "
            "rejected. Output follows this order."
        ),
    )
    cidrs: list[str] = Field(
        default_factory=list,
        description=(
            "Strict IPv4/IPv6 CIDRs to anonymize; host bits must be zero. "
            "Output follows this order."
        ),
    )

    @field_validator("key_hex")
    @classmethod
    def _validate_key(cls, value: str) -> str:
        # Parse once here for validation; the endpoint re-parses the bytes.
        parse_key_hex(value)
        return value

    @field_validator("addresses")
    @classmethod
    def _validate_address_list(cls, values: list[str]) -> list[str]:
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response carrying the offending field and value.
        for value in values:
            parse_address(value)
        return values

    @field_validator("cidrs")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values


class AnonymizeResponse(BaseModel):
    addresses: list[str] = Field(
        description=(
            "Anonymized bare addresses, one per input address, in input order."
        ),
    )
    cidrs: list[str] = Field(
        description=(
            "Canonical anonymized CIDRs, one per input CIDR, in input order; "
            "each keeps the original prefix length with zeroed host bits."
        ),
    )
