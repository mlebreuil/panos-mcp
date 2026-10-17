"""Object models (data-model.md §A): addresses, groups, services, tags, profile groups."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, model_validator


class ObjectKind(StrEnum):
    ADDRESS = "address"
    ADDRESS_GROUP = "address_group"
    SERVICE = "service"
    SERVICE_GROUP = "service_group"
    APPLICATION_GROUP = "application_group"
    TAG = "tag"
    SECURITY_PROFILE_GROUP = "security_profile_group"


class AddressType(StrEnum):
    IP_NETMASK = "ip-netmask"
    IP_RANGE = "ip-range"
    IP_WILDCARD = "ip-wildcard"
    FQDN = "fqdn"


class ObjectBase(BaseModel):
    name: str
    scope: str = Field(description="Defining scope: shared or a device group")
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    effective: bool | None = Field(
        default=None,
        description="True when this definition is the one that applies for the queried scope",
    )


class Address(ObjectBase):
    kind: Literal["address"] = "address"
    type: AddressType
    value: str


class AddressGroup(ObjectBase):
    kind: Literal["address_group"] = "address_group"
    static_members: list[str] | None = None
    dynamic_filter: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> AddressGroup:
        if (self.static_members is None) == (self.dynamic_filter is None):
            raise ValueError("an address group is either static or dynamic")
        return self


class Service(ObjectBase):
    kind: Literal["service"] = "service"
    protocol: Literal["tcp", "udp", "sctp"]
    destination_port: str
    source_port: str | None = None


class ServiceGroup(ObjectBase):
    kind: Literal["service_group"] = "service_group"
    members: list[str] = Field(default_factory=list)


class ApplicationGroup(ObjectBase):
    kind: Literal["application_group"] = "application_group"
    members: list[str] = Field(default_factory=list)


class Tag(ObjectBase):
    kind: Literal["tag"] = "tag"
    color: str | None = None
    comments: str | None = None


class SecurityProfileGroup(ObjectBase):
    kind: Literal["security_profile_group"] = "security_profile_group"
    profiles: dict[str, str] = Field(default_factory=dict)


AnyObject = Annotated[
    Address | AddressGroup | Service | ServiceGroup | ApplicationGroup | Tag | SecurityProfileGroup,
    Field(discriminator="kind"),
]


class ReferrerKind(StrEnum):
    SECURITY_RULE = "security_rule"
    NAT_RULE = "nat_rule"
    ADDRESS_GROUP = "address_group"
    SERVICE_GROUP = "service_group"
    APPLICATION_GROUP = "application_group"
    SECURITY_PROFILE_GROUP = "security_profile_group"
    ADDRESS = "address"
    SERVICE = "service"
    DYNAMIC_ADDRESS_GROUP_FILTER = "dynamic_address_group_filter"


class ObjectReference(BaseModel):
    referrer_kind: ReferrerKind
    referrer_name: str
    scope: str
    position: Literal["pre", "post"] | None = None
    field: str


class ResolvedAddressGroup(BaseModel):
    group: str
    scope: str
    kind: Literal["static", "dynamic"]
    addresses: list[Address] = Field(default_factory=list)
    nested_groups: list[str] = Field(default_factory=list)
    dynamic_filter: str | None = None
    resolved_on: str | None = None
    cycles_detected: list[str] = Field(default_factory=list)
