"""Strict base model for every MCP boundary type.

Zero-Trust Standard §3.1 (*Strict Schema Enforcement*) requires that incoming
payloads be validated against strict schemas and that **excess or undeclared
fields cause immediate rejection**, which is what blocks mass assignment. §4.1
goes further for this system specifically: MCP tool input is validated *"using a
schema independent of and stricter than any schema the model itself proposes."*

:class:`StrictModel` is that schema. Every request and response type in
:mod:`mcp_server.schemas` inherits from it, so the guarantees below hold by
construction rather than by each author remembering to opt in.

What the configuration buys
---------------------------
``extra="forbid"``
    An undeclared field is a hard error, not a silently ignored one. An agent that
    appends ``{"skip_confirmation": true}`` to a proposal gets a 400, not a
    surprise.
``strict=True``
    No lossy coercion. ``"120"`` is not an altitude of 120, and ``True`` is not the
    integer 1. Lossless widening (``int`` → ``float``) is still accepted, because
    JSON has no way to spell ``120.0`` distinctly and rejecting it would be
    pedantry rather than security.
``frozen=True``
    Validated input is immutable. A downstream layer cannot mutate a request after
    the policy engine has authorized it -- the object the gate approved is the
    object that gets used (a TOCTOU defence).
``validate_default=True``
    Defaults are validated like any other value, so a wrong default cannot slip a
    bound.

Note on floats
--------------
``allow_inf_nan=False`` is set globally. ``NaN`` defeats every comparison-based
bound check -- ``NaN > 120`` is ``False``, so a naive ceiling check *passes* -- and
``NaN`` coordinates defeat containment tests the same way. This is the schema-layer
half of the same defence applied in ``dronez.airspace.schema``.

Validate JSON, not dicts
------------------------
``strict=True`` has different meanings for the two input modes, and the difference
matters at the ingress path:

* **JSON mode** (:meth:`StrictModel.parse_json`) accepts JSON's own encodings -- an
  array for a tuple, a string for an enum member -- because those are the only way
  JSON can spell those values. It still rejects every *lossy* coercion: ``"100"`` is
  not a float, ``true`` is not an ``int``, and an unknown enum value is an error.
* **Python mode** (``model_validate`` on a ``dict``) additionally requires exact
  Python types, so it rejects ``[46.5, 24.5]`` for a tuple field and ``"grid"`` for
  an enum.

A request arrives from an MCP client as JSON bytes, so :meth:`parse_json` is the
correct entry point and ``model_validate`` on a hand-built ``dict`` is not. Parsing
to a ``dict`` first and validating that would also mean the JSON parser that ran
before validation was not the strict one -- it would have already accepted duplicate
keys and silently kept the last, which is a request-smuggling shaped problem. Let
Pydantic own the parse.
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict

__all__ = ["SCHEMA_CONTRACT_VERSION", "StrictModel"]

#: Version of the MCP tool-schema contract as a whole. Individual tools carry their
#: own version in ``mcp_server.schemas.tools``; this one moves when the shared
#: envelope of base types changes.
SCHEMA_CONTRACT_VERSION = "mcp-tools/1.0.0"


class StrictModel(BaseModel):
    """Immutable, strictly-validated, closed-world base model.

    Subclasses must not relax ``extra`` or ``strict``. If a payload legitimately
    needs a new field, declare it -- do not open the model.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        allow_inf_nan=False,
        ser_json_inf_nan="strings",
    )

    @classmethod
    def parse_json(cls, raw: str | bytes) -> Self:
        """Validate a request straight from the wire. **This is the ingress path.**

        Pydantic owns the JSON parse, so duplicate keys, trailing data and lossy
        coercions are all rejected by the same strict pass that checks the schema.
        See the module docstring for why validating a pre-parsed ``dict`` is not
        equivalent.
        """
        return cls.model_validate_json(raw)

    def audit_dict(self) -> dict[str, Any]:
        """JSON-safe projection for the append-only ``Command`` record.

        Master Plan §5 requires every proposal to be logged *"regardless of
        outcome, including agent-proposed-but-rejected attempts, since a pattern of
        rejected proposals is itself a security signal."* This is the projection
        that gets written.
        """
        return self.model_dump(mode="json")
