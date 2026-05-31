"""Minimal SARIF 2.1.0 model.

We model the subset OmniScan relies on. Adapters produce a ``SarifLog``; the
normalizer consumes it. This keeps adapters decoupled from the Finding schema.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ArtifactLocation(BaseModel):
    uri: str | None = None


class Region(BaseModel):
    startLine: int | None = None
    startColumn: int | None = None
    endLine: int | None = None
    snippet: dict[str, Any] | None = None


class PhysicalLocation(BaseModel):
    artifactLocation: ArtifactLocation | None = None
    region: Region | None = None


class LogicalLocation(BaseModel):
    name: str | None = None
    fullyQualifiedName: str | None = None
    kind: str | None = None  # "function" | "route" | "parameter" | "flow" ...


class Location(BaseModel):
    physicalLocation: PhysicalLocation | None = None
    logicalLocations: list[LogicalLocation] = Field(default_factory=list)
    # OmniScan extension: DAST url/param, IAST runtime flow, RVD composition path.
    properties: dict[str, Any] = Field(default_factory=dict)


class Message(BaseModel):
    text: str = ""


class Result(BaseModel):
    ruleId: str
    level: str = "warning"  # error | warning | note | none
    message: Message = Field(default_factory=Message)
    locations: list[Location] = Field(default_factory=list)
    # OmniScan extension namespace for tool-specific + RVD enrichment.
    properties: dict[str, Any] = Field(default_factory=dict)


class ReportingDescriptor(BaseModel):
    id: str
    name: str | None = None
    shortDescription: Message | None = None
    fullDescription: Message | None = None
    defaultConfiguration: dict[str, Any] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)


class ToolComponent(BaseModel):
    name: str
    version: str | None = None
    rules: list[ReportingDescriptor] = Field(default_factory=list)


class Tool(BaseModel):
    driver: ToolComponent


class Run(BaseModel):
    tool: Tool
    results: list[Result] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)


class SarifLog(BaseModel):
    version: str = "2.1.0"
    schema_: str = Field(default="https://json.schemastore.org/sarif-2.1.0.json", alias="$schema")
    runs: list[Run] = Field(default_factory=list)

    model_config = {"populate_by_name": True}
