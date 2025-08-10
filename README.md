# sigscope — scope your signatures before you sign (offline)

**sigscope** analyzes what you’re about to sign and tells you the **scope** and
**risk** — without RPC or internet. It works for both **raw messages**
(`personal_sign` / `eth_sign`) and **EIP-712 typed data** (V3/V4 JSON).

## Why this is useful

- Catch misuse of `eth_sign` (hex blobs that smell like calldata).
- See whether an EIP-712 payload is properly **scoped** (chainId, verifyingContract).
- Flag common gotchas in **Permit / Permit2**: unlimited approvals, zero/huge deadlines,
  missing nonces, self-spender, etc.
- Generate a **JSON report** and a tiny **SVG badge** for PRs/CI.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
