"""
Generic REST API Connector
===========================
Flexible connector for custom asset APIs.
Configured via field_mapping dict to map source fields → MACE fields.
"""
from typing import List, Optional
from ..base import BaseConnector, NormalizedAsset


class GenericAPIConnector(BaseConnector):
    """
    Generic REST endpoint connector.
    Supports: bearer token, API key header, basic auth.
    Field mapping: {"source_field": "mace_field"} in config.
    """

    def __init__(self, base_url: str, auth_type: str = "bearer", token: str = "",
                 api_key_header: str = "X-API-Key", field_mapping: Optional[dict] = None,
                 data_path: str = "data", list_endpoint: str = "/assets"):
        super().__init__(base_url)
        self.auth_type = auth_type
        self.token = token
        self.api_key_header = api_key_header
        self.field_mapping = field_mapping or {}
        self.data_path = data_path
        self.list_endpoint = list_endpoint

    async def authenticate(self) -> bool:
        if not self._client:
            return False
        if self.auth_type == "bearer":
            self._client.headers["Authorization"] = f"Bearer {self.token}"
        elif self.auth_type == "api_key":
            self._client.headers[self.api_key_header] = self.token
        elif self.auth_type == "basic":
            import base64
            self._client.headers["Authorization"] = f"Basic {base64.b64encode(self.token.encode()).decode()}"
        return True

    async def fetch_assets(self, limit: int = 500) -> List[NormalizedAsset]:
        await self.authenticate()
        try:
            data = await self._get(self.list_endpoint, params={"limit": limit, "page_size": limit})
            # Navigate to data list using dot-path
            items = data
            for key in self.data_path.split("."):
                if isinstance(items, dict):
                    items = items.get(key, [])
            if not isinstance(items, list):
                return []

            fm = self.field_mapping
            assets = []
            for item in items:
                assets.append(NormalizedAsset(
                    source="custom_api",
                    source_id=str(_get(item, fm.get("id", "id"), "")),
                    hostname=_get(item, fm.get("hostname", "hostname")),
                    ip_address=_get(item, fm.get("ip_address", "ip_address")),
                    mac_address=_get(item, fm.get("mac_address", "mac_address")),
                    os=_get(item, fm.get("os", "os")),
                    asset_class=_get(item, fm.get("asset_class", "asset_class")) or "endpoint",
                    owner=_get(item, fm.get("owner", "owner")),
                    sector=_get(item, fm.get("sector", "sector")),
                    tags=_get(item, fm.get("tags", "tags")) or {},
                    source_confidence=0.80,
                    raw=item,
                ))
            self.logger.info(f"GenericAPI: {len(assets)} records fetched from {self.list_endpoint}")
            return assets
        except Exception as e:
            self.logger.error(f"Generic API fetch error: {e}")
            return []


def _get(obj: dict, path: str, default=None):
    """Navigate dot-path in nested dict."""
    parts = path.split(".")
    cur = obj
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p, default)
        else:
            return default
    return cur
