"""Software Bill of Materials (SBOM) generation.

Produces a CycloneDX-like JSON inventory of project dependencies
for supply chain transparency. Reads from requirements.txt.
"""

import importlib.metadata
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def generate_sbom(requirements_path: Optional[str] = None) -> Dict:
    """Generate an SBOM from installed packages and requirements.txt."""
    components = []

    if requirements_path:
        req_path = Path(requirements_path)
    else:
        req_path = Path(__file__).parent / "requirements.txt"

    declared: Dict[str, str] = {}
    if req_path.exists():
        for line in req_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"([a-zA-Z0-9_.-]+)\[?[^\]]*\]?\s*([><=!~]+\s*[\d.]+)?", line)
            if match:
                name = match.group(1).lower().replace("-", "_")
                version_spec = (match.group(2) or "").strip()
                declared[name] = version_spec

    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name", "").lower().replace("-", "_")
        version = dist.metadata.get("Version", "unknown")
        license_info = dist.metadata.get("License", "")
        homepage = dist.metadata.get("Home-page", "")

        is_declared = name in declared
        component = {
            "type": "library",
            "name": name,
            "version": version,
            "declared": is_declared,
            "license": license_info[:100] if license_info else None,
            "homepage": homepage if homepage else None,
            "purl": f"pkg:pypi/{name}@{version}",
        }
        components.append(component)

    components.sort(key=lambda c: c["name"])
    declared_components = [c for c in components if c["declared"]]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "PromptShield SBOM Generator", "version": "0.3.0"}],
            "component": {
                "type": "application",
                "name": "promptshield-backend",
                "version": "0.3.0",
            },
        },
        "components": declared_components,
        "total_installed": len(components),
        "total_declared": len(declared_components),
    }
