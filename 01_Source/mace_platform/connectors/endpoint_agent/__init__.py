"""
Endpoint Agent connector — ingests MACEAgentReport bundles into the
existing pipeline (UTAG → CDCS → UREA). Replaces the data-collection role
previously filled by the crowdstrike + tenable connectors.
"""
from .connector import EndpointAgentConnector

__all__ = ["EndpointAgentConnector"]
