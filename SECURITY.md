# Security Policy — TSP v0.1

## 🔐 Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Security patches |
| < 0.1   | ❌ Unsupported     |

## 🚨 Reporting a Vulnerability

We take security issues seriously. If you discover a vulnerability in TSP v0.1, please:

1. **Do not** disclose it publicly until we have had time to address it.
2. Email `security@cnomic.dev` with:
   - A description of the vulnerability
   - Steps to reproduce (if applicable)
   - Potential impact assessment
3. We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## ⚠️ Known Security Characteristics (v0.1)

### Fail-Open Behavior
- **Design**: Unknown `sig` formats are accepted with a warning (`fail-open`) to avoid blocking legitimate traffic during early adoption.
- **Risk**: Malicious actors could bypass signature verification by using unsupported `sig` formats.
- **Mitigation**: 
  - Platforms should implement additional trust scoring or rate limiting at the application layer.
  - Future versions will support `fail-secure` mode for production deployments.

### HMAC Key Management
- **Scope**: v0.1 does not specify a key management system (KMS).
- **Recommendation**: 
  - Use out-of-band secure channels for shared secret exchange.
  - Rotate keys periodically and invalidate old cache entries.
  - Never hardcode keys in client-side code.

### TCE-SU2 (Experimental)
- **Status**: Marked `experimental` — not required for basic interoperability.
- **Warning**: 
  - Rotation parameters must be exchanged via secure channels (e.g., Diffie-Hellman).
  - Incorrect quaternion conventions (`[w,x,y,z]` vs `[x,y,z,w]`) may cause silent semantic drift.
  - Do not use for high-assurance applications until v0.2+.

### Canonical JSON (RFC 8785 Approximation)
- **Current**: `ensure_ascii=False` allows non-ASCII characters to pass through unescaped.
- **Risk**: Cross-platform HMAC verification may fail if one implementation strictly escapes Unicode.
- **Mitigation**: 
  - For critical deployments, enforce `ensure_ascii=True` locally.
  - v0.2 will mandate strict RFC 8785 compliance.

## 🛡️ Best Practices for Production Use

1. **Enable Signature Verification**: Always set `sig` to `hmac-sha256:<digest>` in production.
2. **Validate `s` Over `vec`**: The canonical representation `s` is authoritative; re-compute `vec` from `s` when in doubt.
3. **Set Conservative `eps`**: Use `eps_verify=0.30` for semantic verification, `eps_cache=0.65` for caching.
4. **Monitor Cache Hit Rates**: Unexpectedly high hit rates may indicate semantic drift or injection attempts.
5. **Log All `fail-open` Events**: Track unknown `sig` formats for threat intelligence.

## 📜 License & Liability

TSP v0.1 is released under the Apache License 2.0. The protocol is provided "as is" without warranty. Implementers are responsible for assessing security risks in their specific deployment context.

---
*Last updated: April 2026 | Contact: security@cnomic.dev*
