"""
Axonius Asset Intelligence Connector
======================================
Pulls asset inventory from Axonius — the most comprehensive asset data source.
Axonius aggregates from 800+ adapters, so ACS quorum boost applies.
Auth: API key + API secret in Authorization: Bearer base64(key:secret).
"""
from typing import List
from datetime import datetime
from ..base import BaseConnector, NormalizedAsset
import base64


class AxoniusConnector(BaseConnector):
    """
    Axonius REST API v3 — comprehensive asset intelligence.
    Because Axonius aggregates many tools, assets from here get quorum_sources boost.
    """

    def __init__(self, api_key: str, api_secret: str, base_url: str):
        super().__init__(base_url)
        self.api_key = api_key
        self.api_secret = api_secret

    async def authenticate(self) -> bool:
        creds = base64.b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        if self._client:
            self._client.headers.update({
                "Authorization": f"Bearer {creds}",
                "Content-Type": "application/vnd.api+json",
            })
        return True

    async def fetch_assets(self, limit: int = 500) -> List[NormalizedAsset]:
        await self.authenticate()
        try:
            data = await self._get(
                "/api/devices",
                params={
                    "page[size]": min(limit, 2000),
                    "fields[devices]": (
                        "adapters,specific_data.data.hostname,specific_data.data.network_interfaces,"
                        "specific_data.data.os.type,specific_data.data.cloud_id,specific_data.data.agent_versions,"
                        "internal_axon_id,labels,last_seen"
                    ),
                }
            )
            assets = []
            for device in data.get("data", []):
                attrs = device.get("attributes", {})
                specific = attrs.get("specific_data", [{}])

                # Gather IPs and MACs from all network interfaces
                ips, macs = [], []
                for sp in specific:
                    for iface in sp.get("data", {}).get("network_interfaces", []):
                        ips.extend(iface.get("ips", []))
                        macs.extend(iface.get("mac", []) if isinstance(iface.get("mac"), list) else [iface.get("mac")] if iface.get("mac") else [])

                # OS from first specific data
                os_type = (specific[0].get("data", {}).get("os", {}).get("type") if specific else None)

                # Count adapter sources — more adapters = higher confidence
                adapter_count = len(set(attrs.get("adapters", [])))
                confidence = min(0.99, 0.75 + adapter_count * 0.04)

                hostname = None
                for sp in specific:
                    h = sp.get("data", {}).get("hostname")
                    if h:
                        hostname = h
                        break

                assets.append(NormalizedAsset(
                    source="axonius",
                    source_id=device.get("id", attrs.get("internal_axon_id", "")),
                    hostname=hostname,
                    ip_address=ips[0] if ips else None,
                    mac_address=macs[0] if macs else None,
                    os=os_type,
                    asset_class=_axonius_class(os_type, attrs),
                    tags={
                        "axonius_adapters": str(adapter_count),
                        "axonius_labels": ",".join(attrs.get("labels", [])),
                    },
                    source_confidence=confidence,
                    last_seen=_pdt(attrs.get("last_seen")),
                    raw=attrs,
                ))
            self.logger.info(f"Axonius: {len(assets)} devices fetched")
            return assets
        except Exception as e:
            self.logger.error(f"Axonius fetch error: {e}")
            return []


def _axonius_class(os_type: str, attrs: dict) -> str:
    if not os_type:
        return "endpoint"
    os_lower = os_type.lower()
    if "windows server" in os_lower or "ubuntu server" in os_lower or "rhel" in os_lower:
        return "server"
    if attrs.get("specific_data"):
        for sp in attrs["specific_data"]:
            if sp.get("plugin_name") in ("aws_adapter", "azure_adapter", "gcp_adapter"):
                return "cloud_vm"
    return "endpoint"


def _pdt(s):
    if not s: return None
    try: return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except: return None
