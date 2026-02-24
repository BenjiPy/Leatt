"""Process signature verification."""

import hashlib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from enum import Enum

from ..utils.logger import get_logger
from ..utils.platform import PlatformUtils

logger = get_logger("process_signature")


class SignatureStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNSIGNED = "unsigned"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class SignatureInfo:
    """Information about a process signature."""
    status: SignatureStatus
    publisher: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    thumbprint: Optional[str] = None
    timestamp: Optional[str] = None
    error_message: Optional[str] = None


class ProcessSignature:
    """Verify process signatures and authenticity."""
    
    def __init__(self):
        self._signature_cache: dict[str, SignatureInfo] = {}
        self._hash_cache: dict[str, str] = {}
    
    def get_file_hash(self, file_path: Path, algorithm: str = "sha256") -> Optional[str]:
        """Compute hash of a file."""
        path_str = str(file_path)
        
        if path_str in self._hash_cache:
            return self._hash_cache[path_str]
        
        file_hash = PlatformUtils.compute_file_hash(file_path, algorithm)
        
        if file_hash:
            self._hash_cache[path_str] = file_hash
        
        return file_hash
    
    def verify_signature(self, file_path: Path) -> SignatureInfo:
        """Verify the digital signature of a file."""
        path_str = str(file_path)
        
        if path_str in self._signature_cache:
            return self._signature_cache[path_str]
        
        if not file_path.exists():
            return SignatureInfo(
                status=SignatureStatus.ERROR,
                error_message="File not found",
            )
        
        if PlatformUtils.is_windows():
            sig_info = self._verify_windows_signature(file_path)
        else:
            sig_info = SignatureInfo(
                status=SignatureStatus.UNKNOWN,
                error_message="Signature verification not supported on this platform",
            )
        
        self._signature_cache[path_str] = sig_info
        return sig_info
    
    def _verify_windows_signature(self, file_path: Path) -> SignatureInfo:
        """Verify signature on Windows using WinVerifyTrust."""
        try:
            import subprocess
            
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    f"(Get-AuthenticodeSignature '{file_path}').Status"
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            status_str = result.stdout.strip()
            
            if status_str == "Valid":
                publisher_result = subprocess.run(
                    [
                        "powershell",
                        "-Command",
                        f"(Get-AuthenticodeSignature '{file_path}').SignerCertificate.Subject"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                publisher = self._parse_certificate_subject(publisher_result.stdout.strip())
                
                return SignatureInfo(
                    status=SignatureStatus.VALID,
                    publisher=publisher,
                )
            
            elif status_str == "NotSigned":
                return SignatureInfo(status=SignatureStatus.UNSIGNED)
            
            elif status_str in ("HashMismatch", "Invalid"):
                return SignatureInfo(
                    status=SignatureStatus.INVALID,
                    error_message=f"Signature status: {status_str}",
                )
            
            else:
                return SignatureInfo(
                    status=SignatureStatus.UNKNOWN,
                    error_message=f"Unknown status: {status_str}",
                )
        
        except subprocess.TimeoutExpired:
            return SignatureInfo(
                status=SignatureStatus.ERROR,
                error_message="Signature verification timed out",
            )
        except Exception as e:
            logger.debug(f"Error verifying signature for {file_path}: {e}")
            return SignatureInfo(
                status=SignatureStatus.ERROR,
                error_message=str(e),
            )
    
    def _parse_certificate_subject(self, subject: str) -> Optional[str]:
        """Extract common name from certificate subject."""
        if not subject:
            return None
        
        for part in subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                return part[3:].strip('"')
        
        return subject
    
    def is_signed_by_trusted_publisher(self, file_path: Path) -> bool:
        """Check if file is signed by a trusted publisher."""
        sig_info = self.verify_signature(file_path)
        
        if sig_info.status != SignatureStatus.VALID:
            return False
        
        trusted_publishers = [
            "Microsoft",
            "Google",
            "Mozilla",
            "Apple",
            "Adobe",
            "Oracle",
            "Valve",
            "NVIDIA",
            "AMD",
            "Intel",
        ]
        
        if sig_info.publisher:
            publisher_lower = sig_info.publisher.lower()
            return any(tp.lower() in publisher_lower for tp in trusted_publishers)
        
        return False
    
    def compare_hashes(self, file_path: Path, expected_hash: str) -> bool:
        """Compare file hash with expected value."""
        actual_hash = self.get_file_hash(file_path)
        if actual_hash is None:
            return False
        return actual_hash.lower() == expected_hash.lower()
    
    def clear_cache(self) -> None:
        """Clear all caches."""
        self._signature_cache.clear()
        self._hash_cache.clear()
        logger.debug("Signature caches cleared")
    
    def get_cached_hash(self, file_path: Path) -> Optional[str]:
        """Get cached hash if available."""
        return self._hash_cache.get(str(file_path))
