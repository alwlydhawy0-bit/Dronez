"""Deterministic, non-LLM policy engine.

Intentionally empty at Milestone 0. Master Plan §6 forbids flight-capable code
before the Milestone-0 gate closes; the OPA/Rego policy bundle and the
``deploy_recon_waypoint`` validation chain land at Milestone 1.

The one rule that is already binding: nothing in this package may consult an LLM,
import an agent SDK, or accept a natural-language argument. Authorization
decisions are made by deterministic code reading structured input only
(Zero-Trust §4.2 *Deterministic Policy Gate*).
"""
