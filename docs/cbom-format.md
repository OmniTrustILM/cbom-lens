# CBOM Output Format

CBOM-Lens produces a Cryptographic Bill of Materials (CBOM) that conforms to the [CycloneDX BOM 1.6](https://cyclonedx.org/schema/bom-1.6.schema.json) specification.

This document explains how CBOM-Lens models cryptographic assets and how it uses stable `bom-ref` identifiers.

For scanning strategies, see [Scanning use cases & best practices](scanning-use-cases.md). For configuration details, see the [Configuration guide](configuration.md) and [Configuration reference](config.md).

---

## 1. CycloneDX 1.6

- CBOM-Lens uses CycloneDX 1.6 as the base schema for its output.
- Cryptographic assets (certificates, keys, algorithms, etc.) are represented as CycloneDX components with additional properties.

The exact JSON structure is defined by the CycloneDX schema, with CBOM-Lens-specific conventions described below.

---

## 2. Unique yet Secure `bom-ref` Identifiers

CBOM-Lens tracks discovered cryptographic components using content-based identifiers (sha256) during the scanning and correlation phase. This approach enables accurate correlation of identical keys or certificates discovered across different contexts—filesystem scans, container images, and network port scans.

However, content-based hashes are unsuitable for the final CBOM output because hash values can potentially be used to reverse-engineer or identify the underlying cryptographic secrets through rainbow tables or brute-force attacks.

To address this security concern, CBOM-Lens post-processes the CBOM after correlation is complete. It replaces each content-based hash with a randomly generated UUID, providing stable yet cryptographically secure identifiers for every component.

**Key characteristics:**
- **Unique**: Each component receives a distinct identifier within the CBOM
- **Secure**: UUIDs contain no information about the underlying cryptographic material
- **Stable (per CBOM document)**: References remain consistent within a single CBOM document
- **Format-preserving**: Original reference format (e.g., `component@hash`) is maintained as `component@uuid`

> [!WARNING]
> Component references (`bom-ref`) are unique within a single CBOM document only. The same cryptographic component discovered in separate scans will receive different UUIDs in each resulting CBOM.

---

## 3. Example algorithm component

Example of an algorithm component in a CBOM:

```json
{
  "bom-ref": "crypto/algorithm/rsa-4096@3f48a0ca-c944-4ac4-b37b-df51be5ede90",
  "type": "cryptographic-asset",
  "name": "RSA-4096",
  "evidence": {
    "occurrences": [
      { "location": "filesystem:///testing/cert.pem" },
      { "location": "filesystem:///testing/key.pem" }
    ]
  }
}
```

- `evidence.occurrences` lists where the algorithm was observed.
- `bom-ref` uniquely identifies the algorithm + its BOM properties.

---

## 4. Post-Quantum Cryptography (PQC)

Go's standard library does not (yet) implement PQC algorithms, but CBOM-Lens can still **detect** and model them where present.

Support currently includes members of the **ML-DS** family (e.g., `ML-DSA-65`).

Example (truncated) CBOM entry:

```json
{
  "bom-ref": "crypto/algorithm/ml-dsa-65@03acfb52-5eec-466f-88dc-3b9837ffc17e",
  "type": "cryptographic-asset",
  "name": "ML-DSA-65",
  "properties": [
    { "name": "czertainly:component:algorithm:pqc:private_key_size", "value": "4032" },
    { "name": "czertainly:component:algorithm:pqc:public_key_size", "value": "1952" },
    { "name": "czertainly:component:algorithm:pqc:signature_size", "value": "3309" }
  ],
  "evidence": {
    "occurrences": [
      { "location": "testing/pqc.pem" }
    ]
  },
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "ae",
      "parameterSetIdentifier": "65",
      "executionEnvironment": "software-plain-ram",
      "certificationLevel": [ "none" ],
      "cryptoFunctions": [ "sign" ],
      "classicalSecurityLevel": 192,
      "nistQuantumSecurityLevel": 3
    },
    "oid": "2.16.840.1.101.3.4.3.18"
  }
}
```

This representation captures algorithm characteristics and their occurrences while still using stable `bom-ref` identifiers.

---

## 5. Evidence and correlation

CBOM-Lens attaches **evidence** to components to describe where an asset was observed, for example:

- Filesystem paths.
- Container image layers or paths.
- Network endpoints (protocol://host:port).

By combining evidence with stable `bom-ref` identifiers, analysis tools can:

- See all the places where a particular certificate or key is used.
- Understand relationships between algorithms, keys, and certificates.

### Location format

cbom-lens reports source locations as URIs

- Filesystem: `filesystem:///absolute/path`
- Container: `container://<config-name>/<image-ref>/<absolute-path>`
  - <config-name> comes from your configuration
  - <image-ref> can be a tag (e.g., repo:tag) or a digest (e.g., sha256:...)
- Network endpoint: `tcp://host:port`

Example:

`cbom-lens` correlates the same TLS certificate across three sources: the filesystem (`cert.pem`), the container image (`cert.pem`), and the HTTPS server listening on port `:37257`.

```json
"evidence": {
  "occurrences": [
    { "location": "container://docker/image-tag-or-digest//cert.pem" },
    { "location": "filesystem:///tmp/cert.pem" },
    { "location": "tcp://localhost:37257" }
  ]
}
```

---

## 6. Metric Definitions

### 6.1. Sources

- **cbom_lens_sources_total**: Tracks each top-level source that the scanner attempts to process. This includes:
  - Filesystem root directories
  - Docker engines
  - Nmap scan targets

- **cbom_lens_sources_errors**: Counts sources that failed at initialization or access level, preventing any scanning of their contents. This includes:
  - Filesystem does not exists or not accessbile
  - Container engine can't be accessed
  - Nmap binary is missing or can't be executed
  - Other unspecified errors

### 6.2. Files

- **cbom_lens_files_total**: Counts every file path encountered during the scan, regardless of whether it was successfully processed, excluded, or errored.

- **cbom_lens_files_excluded**: Tracks files that were successfully accessed but intentionally skipped based on:
  - File size limits
  - Ignore patterns or rules
  - Other exclusion criteria

- **cbom_lens_files_errors**: Counts files that could not be read or accessed due to:
  - Permission errors
  - File open failures
  - Read errors
  - Other I/O problems

### 6.3. Example in CBOM

```json
"properties": [
  {
    "name": "cbom_lens_files_errors",
    "value": "0"
  },
  {
    "name": "cbom_lens_files_excluded",
    "value": "0"
  },
  {
    "name": "cbom_lens_files_total",
    "value": "3"
  },
  {
    "name": "cbom_lens_sources_errors",
    "value": "0"
  },
  {
    "name": "cbom_lens_sources_total",
    "value": "1"
  }
]
```

---

## 7. Next steps

- For scanning use cases and strategies: see [Scanning use cases & best practices](scanning-use-cases.md).
- For configuration details: see the [Configuration guide](configuration.md) and [Configuration reference](config.md).
- For extending CBOM-Lens to recognize new algorithms or formats: see [Extending detectors](extending-detectors.md).
