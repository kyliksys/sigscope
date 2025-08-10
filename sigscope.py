#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sigscope — scope your signatures before you sign (offline).

What it understands
- Raw strings for personal_sign/eth_sign.
- EIP-712 typed data JSON (fields: types, domain, primaryType, message).
- Common Permit shapes (ERC-2612) and Permit2-like payloads.

Outputs
- Pretty console summary, JSON report, optional SVG badge.
- Risk score (0..100) mapped to SAFE/REVIEW/DANGER.

Examples
  # Raw text (personal_sign)
  $ python sigscope.py analyze "Sign in to Example at 2025-08-10\nNonce: 12345" --pretty

  # Hex-looking blob (eth_sign risk)
  $ python sigscope.py analyze 0xa9059cbb0000000000... --pretty

  # EIP-712 typed data file
  $ python sigscope.py analyze permit.json --pretty --json report.json --svg badge.svg
"""

import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import click
from eth_utils import is_hex, to_checksum_address

# Optional EIP-712 hashing (offline)
try:
    from eth_account.messages import encode_typed_data
    HAVE_EIP712 = True
except Exception:  # pragma: no cover
    HAVE_EIP712 = False

UINT256_MAX = (1 << 256) - 1

# ---------------- utilities ----------------

def looks_hex_blob(s: str) -> bool:
    t = s.strip().lower()
    return t.startswith("0x") and is_hex(t) and len(t) >= 10

def extract_addrs(s: str) -> List[str]:
    # very loose 0x-address scan
    return re.findall(r"0x[a-fA-F0-9]{40}", s)

def extract_urls(s: str) -> List[str]:
    return re.findall(r"https?://[^\s]+", s)

def to_int_maybe(x: Any) -> Optional[int]:
    try:
        if isinstance(x, str) and x.startswith(("0x","0X")) and is_hex(x):
            return int(x, 16)
        return int(x)
    except Exception:
        return None

def lowerhex(x: str) -> str:
    return x.lower() if isinstance(x, str) else x

# ---------------- models ----------------

@dataclass
class Finding:
    level: str   # LOW/MEDIUM/HIGH
    kind: str
    message: str
    context: Dict[str, Any]

@dataclass
class Report:
    kind: str                # raw|eip712|unknown
    summary: Dict[str, Any]  # top-level info (scope fields)
    findings: List[Finding]
    risk_score: int
    risk_label: str

# ---------------- risk scoring ----------------

def score_findings(fs: List[Finding]) -> Tuple[int, str]:
    pts = 0
    for f in fs:
        pts += 45 if f.level == "HIGH" else 20 if f.level == "MEDIUM" else 5
    pts = min(100, pts)
    label = "DANGER" if pts >= 70 else "REVIEW" if pts >= 30 else "SAFE"
    return pts, label

# ---------------- analyzers ----------------

def analyze_raw(msg: str) -> Report:
    fs: List[Finding] = []
    msg_str = str(msg)

    # Hex-looking content → likely `eth_sign` misuse (no domain separation)
    if looks_hex_blob(msg_str):
        fs.append(Finding("HIGH", "hex-blob", "Message looks like hex; avoid eth_sign for calldata-like blobs", {"hint": "use EIP-712 or personal_sign with clear text"}))

    # Embedded addresses/URLs hints
    addrs = extract_addrs(msg_str)
    if addrs:
        fs.append(Finding("MEDIUM", "addresses", "Message contains one or more Ethereum addresses", {"count": len(addrs)}))

    urls = extract_urls(msg_str)
    if urls:
        fs.append(Finding("LOW", "urls", "Message contains URL(s)", {"urls": urls[:3]}))

    # Vague phrases that often appear in phishing
    bait = ["approve", "setApprovalForAll", "private key", "mnemonic", "seed phrase", "airdrop", "urgent", "permission"]
    if any(w.lower() in msg_str.lower() for w in bait):
        fs.append(Finding("MEDIUM", "phrases", "Contains high-risk vocabulary", {}))

    # Nonce & domain hints (good to have)
    if not re.search(r"\bnonce\b", msg_str, flags=re.IGNORECASE):
        fs.append(Finding("LOW", "nonce-missing", "No obvious nonce present in text", {}))
    if not re.search(r"\b(domain|origin|website)\b", msg_str, flags=re.IGNORECASE):
        fs.append(Finding("LOW", "domain-missing", "No explicit domain/origin mentioned", {}))

    scope = {"mode": "personal_sign/eth_sign", "length": len(msg_str)}

    risk, label = score_findings(fs)
    return Report(kind="raw", summary=scope, findings=fs, risk_score=risk, risk_label=label)

def _field(obj: Dict[str, Any], *path, default=None):
    cur = obj
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def looks_like_eip2612(msg: Dict[str, Any]) -> bool:
    # Very common ERC-2612 structure fields
    keys = set(k.lower() for k in msg.keys())
    return {"owner","spender","value","deadline"}.issubset(keys)

def looks_like_permit2(msg: Dict[str, Any]) -> bool:
    keys = set(k.lower() for k in msg.keys())
    return {"details","spender","sigdeadline"}.issubset(keys) or ("permit" in keys and "witness" in keys)

def analyze_eip712(doc: Dict[str, Any]) -> Report:
    fs: List[Finding] = []

    types = _field(doc, "types", default={}) or {}
    domain = _field(doc, "domain", default={}) or {}
    primary = _field(doc, "primaryType", default="")
    message = _field(doc, "message", default={}) or {}

    # Scope summary
    chainId = _field(domain, "chainId")
    verifyingContract = _field(domain, "verifyingContract")
    name = _field(domain, "name")
    version = _field(domain, "version")

    scope = {
        "mode": "EIP-712",
        "primaryType": primary,
        "domain": {
            "name": name,
            "version": version,
            "chainId": chainId,
            "verifyingContract": verifyingContract
        }
    }

    # Basic sanity
    if chainId is None:
        fs.append(Finding("HIGH", "chainId-missing", "EIP-712 domain.chainId is missing", {}))
    if not verifyingContract:
        fs.append(Finding("MEDIUM", "verifyingContract-missing", "EIP-712 domain.verifyingContract is missing", {}))
    if not name or not version:
        fs.append(Finding("LOW", "name/version", "Domain missing name or version", {}))

    # Attempt hashes
    if HAVE_EIP712:
        try:
            _ = encode_typed_data(primitive=doc)  # returns a PreparedMessage
            # We deliberately don't compute the final digest/signature, but success means it's well-formed.
            scope["hashable"] = True
        except Exception as e:
            fs.append(Finding("HIGH", "encoding-error", "EIP-712 encoding failed", {"error": str(e)}))
            scope["hashable"] = False
    else:
        scope["hashable"] = False
        fs.append(Finding("LOW", "hashing-unavailable", "EIP-712 hashing not available (install eth-account)", {}))

    # Targeted checks: ERC-2612 Permit
    if looks_like_eip2612(message):
        owner = lowerhex(str(message.get("owner","")))
        spender = lowerhex(str(message.get("spender","")))
        value = to_int_maybe(message.get("value"))
        deadline = to_int_maybe(message.get("deadline"))
        nonce = message.get("nonce", None)

        if value == UINT256_MAX:
            fs.append(Finding("HIGH", "permit-unlimited", "Permit value is UINT256_MAX (unlimited)", {}))
        if deadline is None:
            fs.append(Finding("MEDIUM", "permit-deadline-missing", "Permit missing deadline", {}))
        elif deadline == 0:
            fs.append(Finding("HIGH", "permit-deadline-zero", "Permit deadline is 0 (never expires)", {}))
        elif deadline > 4_102_444_800:
            fs.append(Finding("LOW", "permit-deadline-far", "Permit deadline far in the future", {"deadline": deadline}))
        if nonce is None:
            fs.append(Finding("LOW", "permit-nonce-missing", "Permit missing nonce", {}))
        if owner == spender and spender:
            fs.append(Finding("MEDIUM", "permit-self", "spender equals owner", {}))

    # Permit2-ish
    if looks_like_permit2(message):
        details = message.get("details") or message.get("permit") or {}
        amount = to_int_maybe(details.get("amount"))
        expiration = to_int_maybe(details.get("expiration")) or to_int_maybe(details.get("sigDeadline")) or to_int_maybe(message.get("sigDeadline"))
        nonce = details.get("nonce") or message.get("nonce")

        if amount == UINT256_MAX:
            fs.append(Finding("HIGH", "permit2-unlimited", "Permit2 amount is UINT256_MAX (unlimited)", {}))
        if expiration is None:
            fs.append(Finding("MEDIUM", "permit2-expiration-missing", "Permit2 missing expiration/sigDeadline", {}))
        elif expiration == 0:
            fs.append(Finding("HIGH", "permit2-expiration-zero", "Permit2 expiration is 0 (never expires)", {}))
        if nonce is None:
            fs.append(Finding("LOW", "permit2-nonce-missing", "Permit2 missing nonce", {}))

    risk, label = score_findings(fs)
    return Report(kind="eip712", summary=scope, findings=fs, risk_score=risk, risk_label=label)

def analyze_input(arg: str) -> Report:
    # Decide: raw string vs file/JSON
    if os.path.isfile(arg):
        with open(arg, "r", encoding="utf-8") as f:
            text = f.read().strip()
        # File may contain a single JSON EIP-712 object or a raw string
        try:
            doc = json.loads(text)
            if isinstance(doc, dict) and "types" in doc and "domain" in doc and "message" in doc:
                return analyze_eip712(doc)
        except Exception:
            pass
        # fallback to raw
        return analyze_raw(text)
    else:
        # Try to parse inline JSON
        try:
            doc = json.loads(arg)
            if isinstance(doc, dict) and "types" in doc and "domain" in doc and "message" in doc:
                return analyze_eip712(doc)
        except Exception:
            pass
        return analyze_raw(arg)

# ---------------- CLI ----------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """sigscope — scope your signatures before you sign (offline)."""
    pass

@cli.command("analyze")
@click.argument("input_arg", type=str)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge.")
@click.option("--pretty", is_flag=True, help="Human-readable output.")
def analyze_cmd(input_arg, json_out, svg_out, pretty):
    """
    Analyze a raw string, a JSON EIP-712 typed data blob, or a file path.
    """
    try:
        rep = analyze_input(input_arg)
    except Exception as e:
        rep = Report(kind="unknown", summary={}, findings=[Finding("HIGH","error","analysis failed",{"error": str(e)})], risk_score=100, risk_label="DANGER")

    if pretty:
        click.echo(f"sigscope — {rep.kind}  risk {rep.risk_score}/100 ({rep.risk_label})")
        if rep.summary:
            click.echo(f"  scope: {rep.summary}")
        for f in rep.findings:
            click.echo(f"   - {f.level}: {f.kind} — {f.message} {f.context}")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({
                "kind": rep.kind,
                "summary": rep.summary,
                "risk_score": rep.risk_score,
                "risk_label": rep.risk_label,
                "findings": [asdict(x) for x in rep.findings],
            }, f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    if svg_out:
        color = "#3fb950" if rep.risk_label == "SAFE" else "#d29922" if rep.risk_label == "REVIEW" else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="720" height="48" role="img" aria-label="sigscope">
  <rect width="720" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    sigscope: {rep.kind} risk {rep.risk_score}/100 ({rep.risk_label})
  </text>
  <circle cx="695" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or svg_out):
        click.echo(json.dumps({
            "kind": rep.kind,
            "summary": rep.summary,
            "risk_score": rep.risk_score,
            "risk_label": rep.risk_label,
            "findings": [asdict(x) for x in rep.findings],
        }, indent=2))

if __name__ == "__main__":
    cli()
