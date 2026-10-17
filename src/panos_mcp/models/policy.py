"""Policy models (data-model.md §A): security and NAT rules."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RuleType(StrEnum):
    SECURITY = "security"
    NAT = "nat"


class Position(StrEnum):
    PRE = "pre"
    POST = "post"
    DEFAULT = "default"


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    RESET_CLIENT = "reset-client"
    RESET_SERVER = "reset-server"
    RESET_BOTH = "reset-both"


class NatType(StrEnum):
    IPV4 = "ipv4"
    NAT64 = "nat64"
    NPTV6 = "nptv6"


class RuleTarget(BaseModel):
    devices: list[str] = Field(default_factory=list, description="Firewall serials")
    negate: bool = False


class Rule(BaseModel):
    name: str
    uuid: str | None = None
    rule_type: RuleType
    scope: str
    position: Position
    order: int = Field(default=0, description="1-based evaluation order in the returned list")
    disabled: bool = False
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    target: RuleTarget | None = None


class SecurityRule(Rule):
    rule_type: RuleType = RuleType.SECURITY
    from_zones: list[str] = Field(default_factory=list)
    to_zones: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    destinations: list[str] = Field(default_factory=list)
    source_users: list[str] = Field(default_factory=list)
    applications: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    negate_source: bool = False
    negate_destination: bool = False
    action: RuleAction
    profile_group: str | None = None
    profiles: dict[str, str] | None = None
    log_start: bool = False
    log_end: bool = True
    log_setting: str | None = None
    schedule: str | None = None


class SourceTranslationKind(StrEnum):
    DYNAMIC_IP_AND_PORT = "dynamic-ip-and-port"
    DYNAMIC_IP = "dynamic-ip"
    STATIC_IP = "static-ip"


class SourceTranslation(BaseModel):
    kind: SourceTranslationKind
    addresses: list[str] = Field(default_factory=list)
    interface: str | None = None
    bidirectional: bool = False


class DestinationTranslation(BaseModel):
    address: str | None = None
    port: int | None = None
    dynamic: bool = False


class NatRule(Rule):
    rule_type: RuleType = RuleType.NAT
    from_zones: list[str] = Field(default_factory=list)
    to_zone: str | None = None
    to_interface: str | None = None
    sources: list[str] = Field(default_factory=list)
    destinations: list[str] = Field(default_factory=list)
    service: str = "any"
    nat_type: NatType = NatType.IPV4
    source_translation: SourceTranslation | None = None
    destination_translation: DestinationTranslation | None = None
