"""FastAPI application exposing POST /normalize, /evaluate, /compare,
/audit-rules, /minimize-policy, /allocate and /anonymize."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app.anonymize import anonymize
from app.policy import (
    allocate,
    audit_rules,
    compare,
    evaluate,
    minimize_policy,
    normalize,
)
from app.schemas import (
    AddressDecision,
    AllocateRequest,
    AllocateResponse,
    AnonymizeRequest,
    AnonymizeResponse,
    AuditRulesRequest,
    AuditRulesResponse,
    CompareRequest,
    CompareResponse,
    EvaluateRequest,
    MinimizePolicyRequest,
    MinimizePolicyResponse,
    NormalizeResponse,
    PolicyRequest,
)

app = FastAPI(
    title="CIDR Policy Normalizer",
    description=(
        "Compute allow-minus-deny for IPv4/IPv6 CIDR lists, returning the "
        "equivalent, non-overlapping, minimum-count CIDR set; evaluate "
        "individual addresses against the same lists via longest-prefix "
        "match; diff two policy sets (baseline vs candidate) over a "
        "scope CIDR; audit each allow/deny rule for its real impact inside "
        "one scope; minimize an allow/deny list to the smallest subset "
        "equivalent inside one scope; allocate non-overlapping subnets "
        "for a list of requests inside one scope, avoiding already-occupied "
        "CIDRs; and prefix-preservingly anonymize bare IPv4/IPv6 addresses "
        "and strict CIDRs under a 256-bit HMAC key for sharing address "
        "lists."
    ),
    version="1.6.0",
)


@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/normalize",
    response_model=NormalizeResponse,
    tags=["policy"],
    summary="Normalize allow/deny CIDR lists into allow minus deny",
)
def normalize_policy(request: PolicyRequest) -> dict:
    return normalize(request.allow, request.deny)


@app.post(
    "/evaluate",
    response_model=list[AddressDecision],
    tags=["policy"],
    summary="Evaluate addresses by longest-prefix match against allow/deny",
    openapi_extra={
        # FastAPI drops Body(examples=...) for model-typed parameters, so the
        # named request examples are attached via openapi_extra; FastAPI merges
        # them into the generated requestBody alongside the schema $ref.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins equal-length ties",
                            "value": {
                                "allow": [
                                    "10.0.0.0/24", "10.0.0.0/25",
                                    "2001:db8::/32",
                                ],
                                "deny": ["10.0.0.0/25"],
                                "addresses": [
                                    "10.0.0.1", "10.0.0.200",
                                    "192.0.2.1", "2001:db8::1",
                                ],
                            },
                        },
                        "invalid_address": {
                            "summary": "CIDR notation in addresses -> HTTP 422",
                            "value": {
                                "allow": ["10.0.0.0/8"],
                                "deny": [],
                                "addresses": ["10.0.0.1/24"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": "One decision per input address, in input order.",
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins ties",
                            "value": [
                                {"decision": "deny",
                                 "matched_cidr": "10.0.0.0/25",
                                 "matched_side": "deny"},
                                {"decision": "allow",
                                 "matched_cidr": "10.0.0.0/24",
                                 "matched_side": "allow"},
                                {"decision": "unmatched",
                                 "matched_cidr": None,
                                 "matched_side": None},
                                {"decision": "allow",
                                 "matched_cidr": "2001:db8::/32",
                                 "matched_side": "allow"},
                            ],
                        },
                    },
                },
            },
        },
        422: {"description": "An address or CIDR in the request is invalid."},
    },
)
def evaluate_policy(request: EvaluateRequest) -> list[dict]:
    return evaluate(request.allow, request.deny, request.addresses)


@app.post(
    "/compare",
    response_model=CompareResponse,
    tags=["policy"],
    summary="Diff baseline vs candidate decisions within a scope CIDR",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": (
                                "Candidate denies a /26 inside the baseline "
                                "allow; deny wins the equal-length tie below"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {
                                    "allow": ["10.0.0.0/24"],
                                    "deny": [],
                                },
                                "candidate": {
                                    "allow": ["10.0.0.0/25"],
                                    "deny": ["10.0.0.128/26"],
                                },
                            },
                        },
                        "identical_policies": {
                            "summary": "Identical sets -> no differences",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {"allow": ["10.0.0.0/24"]},
                                "candidate": {"allow": ["10.0.0.0/24"]},
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Differing regions within scope, sibling-merged per "
                "transition type, plus per-transition address totals."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": "Two allow->deny regions",
                            "value": {
                                "differences": [
                                    {"cidr": "10.0.0.128/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "deny"},
                                    {"cidr": "10.0.0.192/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "unmatched"},
                                ],
                                "transition_counts": {
                                    "allow->deny": "64",
                                    "allow->unmatched": "64",
                                    "deny->allow": "0",
                                    "deny->unmatched": "0",
                                    "unmatched->allow": "0",
                                    "unmatched->deny": "0",
                                },
                            },
                        },
                    },
                },
            },
        },
        422: {"description": "The scope or a CIDR entry is invalid."},
    },
)
def compare_policies(request: CompareRequest) -> dict:
    return compare(
        request.scope,
        request.baseline.allow,
        request.baseline.deny,
        request.candidate.allow,
        request.candidate.deny,
    )


@app.post(
    "/audit-rules",
    response_model=AuditRulesResponse,
    tags=["policy"],
    summary="Classify each allow/deny rule by its real impact inside a scope",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "effective_shadowed_and_out_of_scope": {
                            "summary": (
                                "A broad allow wins where no deny reaches; an "
                                "equal-length allow is shadowed by the deny; "
                                "a disjoint rule is out of scope; duplicate "
                                "allows keep the earliest copy"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/24",
                                    "10.0.0.0/25",
                                    "10.0.0.0/25",
                                ],
                                "deny": [
                                    "10.0.0.0/25",
                                    "10.1.0.0/16",
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One audit result per input rule, grouped by input side and "
                "kept in input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "effective_shadowed_and_out_of_scope": {
                            "summary": "Witness IPs and shadower index sets",
                            "value": {
                                "allow": [
                                    {"side": "allow", "index": 0,
                                     "cidr": "10.0.0.0/24",
                                     "status": "effective",
                                     "witness": "10.0.0.128"},
                                    {"side": "allow", "index": 1,
                                     "cidr": "10.0.0.0/25",
                                     "status": "shadowed",
                                     "shadowed_by": [
                                         {"side": "deny", "index": 0}]},
                                    {"side": "allow", "index": 2,
                                     "cidr": "10.0.0.0/25",
                                     "status": "shadowed",
                                     "shadowed_by": [
                                         {"side": "deny", "index": 0}]},
                                ],
                                "deny": [
                                    {"side": "deny", "index": 0,
                                     "cidr": "10.0.0.0/25",
                                     "status": "effective",
                                     "witness": "10.0.0.0"},
                                    {"side": "deny", "index": 1,
                                     "cidr": "10.1.0.0/16",
                                     "status": "out_of_scope"},
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/rule CIDR, or a rule whose address family does "
                "not match the scope."
            ),
        },
    },
)
def audit_policy_rules(request: AuditRulesRequest) -> dict:
    return audit_rules(request.scope, request.allow, request.deny)


@app.post(
    "/minimize-policy",
    response_model=MinimizePolicyResponse,
    tags=["policy"],
    summary=(
        "Reduce allow/deny rules to the minimum subset equivalent in a scope"
    ),
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "minimum_subset_with_witnesses": {
                            "summary": (
                                "Two overlapping allows are redundant; "
                                "lexicographically smallest (side, index) "
                                "set is retained with witnesses"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/24",
                                    "10.0.0.0/25",
                                ],
                                "deny": ["10.0.0.128/25"],
                            },
                        },
                        "too_many_rules": {
                            "summary": "More than 16 rules total -> HTTP 422",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/26", "10.0.0.64/26",
                                    "10.0.0.128/26", "10.0.0.192/26",
                                    "10.0.0.0/27", "10.0.0.32/27",
                                    "10.0.0.64/27", "10.0.0.96/27",
                                    "10.0.0.128/27",
                                ],
                                "deny": [
                                    "10.0.0.160/27", "10.0.0.192/27",
                                    "10.0.0.224/27", "10.0.0.0/28",
                                    "10.0.0.16/28", "10.0.0.32/28",
                                    "10.0.0.48/28", "10.0.0.80/28",
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "The unique minimum-cardinality rule subset, with retained "
                "and removed references in original input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "minimum_subset_with_witnesses": {
                            "summary": "allow index 0 covers the lower half",
                            "value": {
                                "retained": [
                                    {"side": "allow", "index": 0,
                                     "cidr": "10.0.0.0/24",
                                     "witness": "10.0.0.0"},
                                    {"side": "deny", "index": 0,
                                     "cidr": "10.0.0.128/25",
                                     "witness": "10.0.0.128"},
                                ],
                                "removed": [
                                    {"side": "allow", "index": 1,
                                     "cidr": "10.0.0.0/25"},
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/rule CIDR, a rule whose address family does "
                "not match the scope, or more than 16 allow/deny rules in "
                "total."
            ),
        },
    },
)
def minimize_policy_rules(request: MinimizePolicyRequest) -> dict:
    return minimize_policy(request.scope, request.allow, request.deny)


@app.post(
    "/allocate",
    response_model=AllocateResponse,
    tags=["policy"],
    summary="Allocate non-overlapping subnets for requests inside a scope",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "lexicographic_with_backtracking": {
                            "summary": (
                                "Greedy first-fit for 'small' would block "
                                "'big'; backtracking finds the lexicographically"
                                " smallest complete plan"
                            ),
                            "value": {
                                "scope": "10.0.0.0/23",
                                "occupied": ["10.0.1.0/25"],
                                "requests": [
                                    {"id": "small", "prefix_length": 25},
                                    {"id": "big", "prefix_length": 24},
                                ],
                            },
                        },
                        "infeasible": {
                            "summary": "Two /25s do not fit beside the occupied /25 -> HTTP 409",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "occupied": ["10.0.0.0/25"],
                                "requests": [
                                    {"id": "x", "prefix_length": 25},
                                    {"id": "y", "prefix_length": 25},
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Allocations in request order plus the remaining free space "
                "as a minimal CIDR set with its decimal address count."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "lexicographic_with_backtracking": {
                            "summary": "Lexicographically smallest complete plan",
                            "value": {
                                "allocations": [
                                    {"id": "small", "cidr": "10.0.1.128/25"},
                                    {"id": "big", "cidr": "10.0.0.0/24"},
                                ],
                                "remaining": [],
                                "remaining_addresses": "0",
                            },
                        },
                    },
                },
            },
        },
        409: {
            "description": (
                "No complete assignment exists; no partial allocation is "
                "returned."
            ),
        },
        422: {
            "description": (
                "Invalid scope/occupied CIDR, occupied entry outside the "
                "scope or of the wrong family, overlapping occupied CIDRs, "
                "duplicate request id, or invalid prefix length."
            ),
        },
    },
)
def allocate_subnets(request: AllocateRequest) -> dict:
    result = allocate(
        request.scope,
        request.occupied,
        [(item.id, item.prefix_length) for item in request.requests],
    )
    if result is None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"no complete allocation satisfies all requests within "
                f"scope {request.scope!r}; no partial allocation returned"
            ),
        )
    return result


@app.post(
    "/anonymize",
    response_model=AnonymizeResponse,
    tags=["anonymize"],
    summary=(
        "Prefix-preserving keyed anonymization of bare addresses and CIDRs"
    ),
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "addresses_and_strict_cidrs": {
                            "summary": (
                                "Bare IPv4/IPv6 addresses and strict CIDRs; "
                                "shared prefixes stay shared"
                            ),
                            "value": {
                                "key_hex": (
                                    "0123456789abcdef0123456789abcdef"
                                    "0123456789abcdef0123456789abcdef"
                                ),
                                "addresses": [
                                    "192.168.0.1",
                                    "192.168.0.2",
                                    "2001:db8::1",
                                ],
                                "cidrs": [
                                    "10.0.0.0/8",
                                    "192.168.0.0/24",
                                    "2001:db8::/32",
                                ],
                            },
                        },
                        "bad_key": {
                            "summary": "key_hex is not 64 hex chars -> HTTP 422",
                            "value": {"key_hex": "deadbeef", "addresses": []},
                        },
                        "cidr_with_host_bits": {
                            "summary": "Host bits set in a CIDR -> HTTP 422",
                            "value": {
                                "key_hex": (
                                    "0123456789abcdef0123456789abcdef"
                                    "0123456789abcdef0123456789abcdef"
                                ),
                                "cidrs": ["10.0.0.1/24"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Anonymized addresses and canonical CIDR images, each list "
                "keeping its input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "addresses_and_strict_cidrs": {
                            "summary": (
                                "192.168.0.1/2 still share a /30; the /8 "
                                "stays a /8"
                            ),
                            "value": {
                                "addresses": [
                                    "236.222.104.188",
                                    "236.222.104.191",
                                    "d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a",
                                ],
                                "cidrs": [
                                    "77.0.0.0/8",
                                    "236.222.104.0/24",
                                    "d5af:46c8::/32",
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "key_hex is not exactly 64 hexadecimal characters, an "
                "address is invalid or uses CIDR notation, or a CIDR is "
                "invalid or has host bits set."
            ),
        },
    },
)
def anonymize_lists(request: AnonymizeRequest) -> dict:
    return anonymize(request.key_hex, request.addresses, request.cidrs)
