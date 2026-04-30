import json
from dataclasses import dataclass, asdict

import requests
import tldextract
from django.core.cache import cache

from reNgine.common_func import get_netlas_key


@dataclass
class WhoisResult:
    status: str
    provider: str
    category: str
    message: str
    data: dict
    raw_keys: list
    used_fallback: bool = False

    def to_dict(self):
        return asdict(self)


class NetlasWhoisProvider:
    provider_name = "netlas"

    def query(self, target):
        netlas_key = get_netlas_key()
        if not netlas_key:
            return WhoisResult("failed", self.provider_name, "config_error", "Netlas API key is not configured.", {}, [])

        headers = {"Authorization": f"Bearer {netlas_key}", "Accept": "application/json"}
        url = f"https://app.netlas.io/api/domains/{target}"
        try:
            response = requests.get(url, headers=headers, timeout=12)
        except requests.exceptions.Timeout:
            return WhoisResult("failed", self.provider_name, "timeout", "Netlas request timeout.", {}, [])
        except requests.RequestException as exc:
            return WhoisResult("failed", self.provider_name, "temporary_error", f"Netlas request failed: {exc}", {}, [])

        if response.status_code in (401, 403):
            return WhoisResult("failed", self.provider_name, "auth_error", "Netlas authentication failed.", {}, [])
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            msg = "Netlas request rate limited."
            if retry_after:
                msg += f" Retry-After: {retry_after}."
            return WhoisResult("failed", self.provider_name, "rate_limit", msg, {}, [])
        if response.status_code >= 500:
            return WhoisResult("failed", self.provider_name, "temporary_error", "Netlas server error.", {}, [])

        try:
            payload = response.json()
        except json.JSONDecodeError:
            return WhoisResult("failed", self.provider_name, "parser_error", "Failed to parse Netlas JSON response.", {}, [])

        whois_data = payload.get("whois") if isinstance(payload, dict) else None
        if not whois_data:
            return WhoisResult("degraded", self.provider_name, "no_data", "Netlas returned no WHOIS data.", payload if isinstance(payload, dict) else {}, list(payload.keys()) if isinstance(payload, dict) else [])

        return WhoisResult("ok", self.provider_name, "ok", "WHOIS data retrieved from Netlas.", payload, list(payload.keys()))


class RdapWhoisProvider:
    provider_name = "rdap"
    bootstrap_url = "https://data.iana.org/rdap/dns.json"

    def _registrable_domain(self, target):
        ext = tldextract.extract(target)
        return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else target

    def query(self, target):
        domain = self._registrable_domain(target)
        try:
            boot = requests.get(self.bootstrap_url, timeout=10)
            boot.raise_for_status()
            services = boot.json().get("services", [])
        except requests.exceptions.Timeout:
            return WhoisResult("failed", self.provider_name, "timeout", "RDAP bootstrap timeout.", {}, [])
        except Exception:
            return WhoisResult("failed", self.provider_name, "parser_error", "Unable to parse RDAP bootstrap.", {}, [])

        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        rdap_base = None
        for entry in services:
            tlds, urls = entry
            if tld in [x.lower() for x in tlds] and urls:
                rdap_base = urls[0]
                break
        if not rdap_base:
            return WhoisResult("degraded", self.provider_name, "rdap_not_available", "RDAP is not available for TLD.", {}, [])

        try:
            resp = requests.get(f"{rdap_base.rstrip('/')}/domain/{domain}", timeout=12)
        except requests.exceptions.Timeout:
            return WhoisResult("failed", self.provider_name, "timeout", "RDAP request timeout.", {}, [])
        except requests.RequestException as exc:
            return WhoisResult("failed", self.provider_name, "temporary_error", f"RDAP request failed: {exc}", {}, [])

        if resp.status_code == 404:
            return WhoisResult("degraded", self.provider_name, "rdap_not_found", "Domain not found in RDAP.", {}, [])
        try:
            resp.raise_for_status()
            data = resp.json()
        except json.JSONDecodeError:
            return WhoisResult("failed", self.provider_name, "parser_error", "Failed to parse RDAP JSON response.", {}, [])
        except Exception as exc:
            return WhoisResult("failed", self.provider_name, "temporary_error", f"RDAP lookup failed: {exc}", {}, [])

        mapped = {
            "whois": {
                "created_date": next((evt.get("eventDate") for evt in data.get("events", []) if evt.get("eventAction") in ["registration", "registered"]), None),
                "expiration_date": next((evt.get("eventDate") for evt in data.get("events", []) if evt.get("eventAction") == "expiration"), None),
                "updated_date": next((evt.get("eventDate") for evt in data.get("events", []) if evt.get("eventAction") in ["last changed", "last update of RDAP database"]), None),
                "status": data.get("status", []),
            },
            "dns": {
                "ns": [host.get("ldhName") for host in data.get("nameservers", []) if host.get("ldhName")],
            },
            "related_domains": [],
        }
        return WhoisResult("ok", self.provider_name, "ok", "WHOIS data retrieved from RDAP.", mapped, list(data.keys()))


class WhoisService:
    def __init__(self, netlas_provider=None, rdap_provider=None):
        self.netlas_provider = netlas_provider or NetlasWhoisProvider()
        self.rdap_provider = rdap_provider or RdapWhoisProvider()

    def query(self, target):
        netlas_result = self.netlas_provider.query(target)
        if netlas_result.status == "ok":
            return netlas_result

        if netlas_result.category in {"config_error", "auth_error", "rate_limit", "timeout", "no_data", "temporary_error", "parser_error"}:
            rdap_result = self.rdap_provider.query(target)
            rdap_result.used_fallback = True
            if rdap_result.status == "ok":
                return rdap_result
            return WhoisResult("failed", rdap_result.provider, rdap_result.category, rdap_result.message, {}, rdap_result.raw_keys, True)
        return netlas_result


def acquire_whois_lock(target, ttl=60):
    return cache.add(f"whois-lock:{target}", "1", timeout=ttl)


def release_whois_lock(target):
    cache.delete(f"whois-lock:{target}")


def mask_sensitive_value(value):
    if not value:
        return value
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}****{value[-2:]}"
