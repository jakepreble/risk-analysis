from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class VendorResponse:
    vendor_name: str
    responses: Dict[str, str]