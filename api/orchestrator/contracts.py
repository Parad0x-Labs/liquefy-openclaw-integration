from pydantic import BaseModel, Field, model_validator
from typing import List, Optional, Literal

EngineType = Literal["inprocess", "external_service", "external_binary"]


class SniffRule(BaseModel):
    """Optional content-sniffing rule for ambiguous extensions (.log, .txt)."""
    contains_any: List[str] = Field(default_factory=list)
    contains_all: List[str] = Field(default_factory=list)
    regex_any: List[str] = Field(default_factory=list)


class EngineCapabilities(BaseModel):
    mimetypes: List[str] = Field(default_factory=list)
    extensions: List[str] = Field(default_factory=list)


class EngineManifest(BaseModel):
    id: str
    type: EngineType
    api_version: str = "1.0"
    priority: int = Field(default=10, ge=0, le=1000)
    capabilities: EngineCapabilities
    sniff: Optional[SniffRule] = None

    entrypoint: Optional[str] = None
    endpoint: Optional[str] = None
    cmd: Optional[List[str]] = None

    @model_validator(mode="after")
    def validate_by_type(self):
        if self.type == "inprocess" and not self.entrypoint:
            raise ValueError("entrypoint is required for type=inprocess")
        if self.type == "external_service" and not self.endpoint:
            raise ValueError("endpoint is required for type=external_service")
        if self.type == "external_binary" and not self.cmd:
            raise ValueError("cmd (list of args) is required for type=external_binary")
        return self
