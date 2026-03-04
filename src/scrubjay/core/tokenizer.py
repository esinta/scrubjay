"""Type-preserving replacement generation.

Generates synthetic replacement values that preserve the structural properties
of the original data. Each FieldType has a dedicated generator that produces
valid-looking replacements while ensuring determinism and uniqueness within
a session.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from scrubjay.core.types import FieldType


class Tokenizer:
    """Generates type-preserving token replacements for sensitive values.

    Attributes:
        seed: Session seed for reproducibility.
    """

    def __init__(self, seed: str | None = None):
        """Initialize with optional seed for reproducibility.

        Args:
            seed: If None, a random seed is generated per session.
        """
        self.seed = seed or os.urandom(16).hex()
        self._counters: dict[str, int] = {}
        self._generated: dict[tuple[str, FieldType], str] = {}
        self._username_map: dict[str, str] = {}  # real_username -> USER-XXXX
        self._domain_map: dict[str, str] = {}  # real_domain -> ORG-XXXX.tld
        self._path_map: dict[str, str] = {}  # real_path_segment -> PATH-XXXX
        self._share_map: dict[str, str] = {}  # real_share -> SHARE-XXXX
        self._unit_map: dict[str, str] = {}  # real_ou -> UNIT-XXXX
        self._org_map: dict[str, str] = {}  # real_dc -> ORG-XXXX

    def _next_counter(self, prefix: str) -> int:
        """Get the next counter value for a given prefix."""
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        return self._counters[prefix]

    def generate(self, real_value: str, field_type: FieldType) -> str:
        """Generate a type-preserving replacement for a real value.

        Args:
            real_value: The original sensitive value.
            field_type: The semantic type determining replacement strategy.

        Returns:
            A synthetic replacement token preserving the value's structure.
        """
        key = (real_value, field_type)
        if key in self._generated:
            return self._generated[key]

        generators = {
            FieldType.EMAIL: self._generate_email,
            FieldType.USERNAME: self._generate_username,
            FieldType.HOSTNAME: self._generate_hostname,
            FieldType.GROUP_NAME: self._generate_group_name,
            FieldType.APP_NAME: self._generate_app_name,
            FieldType.PERSON_NAME: self._generate_person_name,
            FieldType.ACCOUNT_ID: self._generate_account_id,
            FieldType.EMAIL_SUBJECT: self._generate_email_subject,
            FieldType.FILENAME: self._generate_filename,
            FieldType.DN: self._generate_dn,
            FieldType.URL_INTERNAL: self._generate_url_internal,
            FieldType.FREETEXT: self._generate_freetext,
            FieldType.DOMAIN_INTERNAL: self._generate_domain_internal,
            FieldType.MAC_ADDRESS: self._generate_mac_address,
            FieldType.CERTIFICATE_CN: self._generate_certificate_cn,
            FieldType.FILE_PATH: self._generate_file_path,
            FieldType.UNC_PATH: self._generate_unc_path,
            FieldType.PASSTHROUGH: self._generate_passthrough,
        }

        gen = generators.get(field_type)
        if gen is None:
            result = real_value
        else:
            result = gen(real_value)

        self._generated[key] = result
        return result

    def _get_username_token(self, username: str) -> str:
        """Get or create a consistent USER token for a username."""
        lower = username.lower()
        if lower not in self._username_map:
            n = self._next_counter("USER")
            self._username_map[lower] = f"USER-{n:04d}"
        return self._username_map[lower]

    def _get_domain_token(self, domain: str) -> str:
        """Get or create a consistent ORG domain token, preserving TLD."""
        lower = domain.lower()
        if lower not in self._domain_map:
            parts = lower.split(".")
            if len(parts) >= 2:
                tld = parts[-1]
            else:
                tld = "com"
            n = self._next_counter("ORG")
            self._domain_map[lower] = f"ORG-{n:03d}.{tld}"
        return self._domain_map[lower]

    def _get_path_token(self, segment: str) -> str:
        """Get or create a consistent PATH token for a path segment."""
        lower = segment.lower()
        if lower not in self._path_map:
            n = self._next_counter("PATH")
            self._path_map[lower] = f"PATH-{n:03d}"
        return self._path_map[lower]

    def _get_share_token(self, share: str) -> str:
        """Get or create a consistent SHARE token."""
        lower = share.lower()
        if lower not in self._share_map:
            n = self._next_counter("SHARE")
            self._share_map[lower] = f"SHARE-{n:03d}"
        return self._share_map[lower]

    def _get_host_token(self, hostname: str) -> str:
        """Get or create a HOST token, preserving TLD portion."""
        lower = hostname.lower()
        # Check if already generated as a full HOSTNAME type
        key = (hostname, FieldType.HOSTNAME)
        if key in self._generated:
            return self._generated[key]
        # Generate a new one with TLD preservation
        parts = lower.split(".")
        n = self._next_counter("HOST")
        host_token = f"HOST-{n:04d}"
        if len(parts) >= 3:
            # Preserve last two segments for internal domains
            tld = ".".join(parts[-2:])
            result = f"{host_token}.{tld}"
        elif len(parts) == 2:
            tld = parts[-1]
            result = f"{host_token}.{tld}"
        else:
            result = host_token
        self._generated[key] = result
        return result

    # ── Per-type generators ──

    def _generate_email(self, real_value: str) -> str:
        """Preserves email structure: local@domain -> USER-XXXX@ORG-XXX.tld."""
        parts = real_value.split("@", 1)
        if len(parts) != 2:
            return f"USER-{self._next_counter('USER'):04d}@redacted.com"
        local, domain = parts
        user_token = self._get_username_token(local)
        domain_token = self._get_domain_token(domain)
        return f"{user_token}@{domain_token}"

    def _generate_username(self, real_value: str) -> str:
        """Simple counter: username -> USER-XXXX."""
        return self._get_username_token(real_value)

    def _generate_hostname(self, real_value: str) -> str:
        """Preserves TLD: host.corp.internal -> HOST-XXXX.corp.internal."""
        return self._get_host_token(real_value)

    def _generate_group_name(self, real_value: str) -> str:
        """Simple counter: group -> GROUP-XXXX."""
        n = self._next_counter("GROUP")
        return f"GROUP-{n:04d}"

    def _generate_app_name(self, real_value: str) -> str:
        """Simple counter: app -> APP-XXXX."""
        n = self._next_counter("APP")
        return f"APP-{n:04d}"

    def _generate_person_name(self, real_value: str) -> str:
        """Simple counter: name -> PERSON-XXXX."""
        n = self._next_counter("PERSON")
        return f"PERSON-{n:04d}"

    def _generate_account_id(self, real_value: str) -> str:
        """Simple counter: account_id -> ACCT-XXXX."""
        n = self._next_counter("ACCT")
        return f"ACCT-{n:04d}"

    def _generate_email_subject(self, real_value: str) -> str:
        """Simple counter: subject -> SUBJECT-XXXX."""
        n = self._next_counter("SUBJECT")
        return f"SUBJECT-{n:04d}"

    def _generate_filename(self, real_value: str) -> str:
        """Preserves file extension: report.xlsx -> FILE-XXXX.xlsx."""
        dot_idx = real_value.rfind(".")
        if dot_idx > 0:
            ext = real_value[dot_idx:]
        else:
            ext = ""
        n = self._next_counter("FILE")
        return f"FILE-{n:04d}{ext}"

    def _generate_dn(self, real_value: str) -> str:
        """Parse DN components and replace with consistent tokens.

        CN=jsmith,OU=Finance,DC=corp -> CN=USER-0001,OU=UNIT-001,DC=ORG-001
        """
        parts = re.split(r",\s*", real_value)
        result_parts = []
        for part in parts:
            if "=" not in part:
                result_parts.append(part)
                continue
            prefix, value = part.split("=", 1)
            prefix_upper = prefix.strip().upper()
            if prefix_upper == "CN":
                token = self._get_username_token(value)
                result_parts.append(f"CN={token}")
            elif prefix_upper == "OU":
                lower = value.lower()
                if lower not in self._unit_map:
                    n = self._next_counter("UNIT")
                    self._unit_map[lower] = f"UNIT-{n:03d}"
                result_parts.append(f"OU={self._unit_map[lower]}")
            elif prefix_upper == "DC":
                lower = value.lower()
                if lower not in self._org_map:
                    n = self._next_counter("ORG")
                    self._org_map[lower] = f"ORG-{n:03d}"
                result_parts.append(f"DC={self._org_map[lower]}")
            else:
                result_parts.append(part)
        return ",".join(result_parts)

    def _generate_url_internal(self, real_value: str) -> str:
        """Preserve scheme, replace host and path.

        https://vault.corp/v1/secret -> https://HOST-XXXX/PATH-XXX
        """
        try:
            parsed = urlparse(real_value)
        except Exception:
            return real_value

        scheme = parsed.scheme or "https"
        host = parsed.hostname or parsed.netloc or ""
        host_token = self._get_host_token(host) if host else "HOST-0000"

        path = parsed.path.strip("/")
        if path:
            path_token = self._get_path_token(path)
            return f"{scheme}://{host_token}/{path_token}"
        return f"{scheme}://{host_token}"

    def _generate_freetext(self, real_value: str) -> str:
        """FREETEXT is not handled by tokenizer directly. Return unchanged."""
        return real_value

    def _generate_domain_internal(self, real_value: str) -> str:
        """Preserve TLD, replace domain: corp.internal -> ORG-XXX.internal."""
        return self._get_domain_token(real_value)

    def _generate_mac_address(self, real_value: str) -> str:
        """Use locally-administered prefix + counter as last bytes.

        aa:bb:cc:dd:ee:ff -> 02:00:00:00:00:XX
        """
        n = self._next_counter("MAC")
        high = (n >> 8) & 0xFF
        low = n & 0xFF
        return f"02:00:00:00:{high:02x}:{low:02x}"

    def _generate_certificate_cn(self, real_value: str) -> str:
        """Simple counter: cert CN -> CERT-XXXX."""
        n = self._next_counter("CERT")
        return f"CERT-{n:04d}"

    def _generate_file_path(self, real_value: str) -> str:
        r"""Preserve drive letter, extract username, preserve extension.

        C:\Users\jsmith\Documents\report.docx
        -> C:\Users\USER-0001\PATH-001\FILE-0001.docx
        """
        # Detect separator
        if "\\" in real_value:
            sep = "\\"
        else:
            sep = "/"

        parts = real_value.split(sep)
        result = []

        # Preserve drive letter or root
        i = 0
        if parts and (re.match(r"^[A-Za-z]:$", parts[0]) or parts[0] == ""):
            result.append(parts[0])
            i = 1

        # Check for Users directory pattern
        users_idx = None
        for j in range(i, len(parts)):
            if parts[j].lower() == "users":
                users_idx = j
                break

        if users_idx is not None:
            # Copy up to and including "Users"
            for j in range(i, users_idx + 1):
                result.append(parts[j])
            i = users_idx + 1

            # Tokenize the username
            if i < len(parts):
                username = parts[i]
                user_token = self._get_username_token(username)
                result.append(user_token)
                i += 1

        # Handle remaining path segments
        for j in range(i, len(parts)):
            segment = parts[j]
            if j == len(parts) - 1 and "." in segment:
                # Last segment with extension = filename
                dot_idx = segment.rfind(".")
                ext = segment[dot_idx:]
                n = self._next_counter("FILE")
                result.append(f"FILE-{n:04d}{ext}")
            elif segment:
                path_token = self._get_path_token(segment)
                result.append(path_token)

        return sep.join(result)

    def _generate_unc_path(self, real_value: str) -> str:
        r"""Preserve UNC path structure.

        \\fileserver\share\folder -> \\HOST-XXXX\SHARE-XXX\PATH-XXX
        """
        # Strip leading backslashes
        stripped = real_value.lstrip("\\")
        parts = stripped.split("\\")

        result_parts = []
        for idx, part in enumerate(parts):
            if not part:
                continue
            if idx == 0:
                # Server name -> HOST token
                host_token = self._get_host_token(part)
                result_parts.append(host_token)
            elif idx == 1:
                # Share name -> SHARE token
                share_token = self._get_share_token(part)
                result_parts.append(share_token)
            else:
                # Remaining segments -> PATH tokens
                path_token = self._get_path_token(part)
                result_parts.append(path_token)

        return "\\\\" + "\\".join(result_parts)

    def _generate_passthrough(self, real_value: str) -> str:
        """PASSTHROUGH: return input unchanged."""
        return real_value
