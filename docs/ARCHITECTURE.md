# Architecture

## Goal

SecureGuard is an offline Python and C/C++ code auditor. Python uses the built-in AST parser. C/C++ uses a dependency-free lexical adapter for common source-to-sink paths and unsafe APIs. It is intentionally different from a generic multi-language scanner because its analysis focuses on tainted values reaching specific dangerous operations.

## Pipeline

1. **Language Analysis Agent** parses `.py` files with AST and tracks simple assignments from likely input sources. For C/C++, a lexical adapter checks function parameters, common input APIs, and dangerous sinks.
2. **RAG Retrieval Agent** normalizes SecureGuard JSONL/JSON and common MITRE-style CWE schemas, then searches local knowledge bases with BM25 by default. An optional local Ollama embedding model can build a chunk-level semantic index; exact CWE matches from the static analyzer still take priority. Retrieval filters by source language and returns the matching passage with its CWE record.
3. **Local LLM Auditor Agent** optionally sends the source plus retrieved references to an Ollama model on loopback only. It may identify additional issues that are not in the static rules.
4. **Evidence Gate Agent** accepts model findings only when the CWE identifier is valid and the claimed evidence exactly matches the complete cited source line or a distinctive exact substring on it. A unique exact substring can correct a model off-by-one line number. It can strip a copied `NUMBER |` prefix because the model prompt shows numbered source lines.
5. **Report Agent** writes Markdown, JSON findings, SARIF 2.1.0, and run metadata. Evidence on lines classified as hard-coded credentials is redacted in exported reports.

The static analyzer scans the whole file. The model prompt is divided into chunks of up to about 7,000 source characters, with a small overlap to preserve context for local models. Run metadata records the number of requests, proposals, accepted findings, and evidence-gate rejections. Embeddings are optional and are generated locally; their index is rebuilt for each run. The project never sends code to a non-loopback host.

## Current coverage

- Python untrusted input reaching `eval`/`exec`
- Tainted values reaching shell-based subprocess calls or `os.system`/`os.popen`
- Tainted SQL query strings passed to common `.execute()` methods
- Untrusted data passed to `pickle` or unsafe YAML deserialization
- Tainted values used in file paths
- Tainted template source passed to `render_template_string`
- Credential-like variable names assigned string literals
- Additional findings proposed by the optional local model, gated by exact-line evidence
- C/C++ use of unsafe buffer functions, unbounded `%s` input, shell calls, uncontrolled format strings, and tainted copy sizes

## Limits

This is a classroom prototype, not a proof of safety. Python taint tracking is intraprocedural and conservative. C/C++ scanning is lexical, not compiler-backed, and does not fully model macros, aliases, pointer arithmetic, sanitizers, native extensions, or arbitrary control flow. A finding needs human review, and a clean report does not prove that code is vulnerability-free. RAG provides context; it does not train or fine-tune the model.
