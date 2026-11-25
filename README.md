# SecureGuard: Offline Python and C/C++ Security Auditor

SecureGuard is a Secure Coding project that reviews Python and C/C++ source for risky data flows. Python is parsed with the built-in AST module. C/C++ uses a dependency-free lexical analyzer for common input-to-sink paths and unsafe APIs. The project also has a local RAG knowledge base and an optional Ollama review stage.

## What it does

1. Parses Python with Python's built-in `ast` module and tracks simple flows from likely untrusted input to sensitive operations.
2. Scans C/C++ for common input-to-sink paths, unsafe buffer APIs, shell execution, and format-string risks.
3. Retrieves related CWE descriptions, code examples, mitigations, and CVE references from local JSON/JSONL knowledge bases using BM25; for static findings it looks up the exact CWE first.
4. Optionally asks an Ollama model running on the same computer to review the file and retrieved references.
5. Rejects model findings unless their CWE identifier is well formed and the quoted evidence exactly matches the source line or a distinctive fragment on it; reports separate accepted proposals from genuinely new model findings and duplicates.
6. Writes Markdown, JSON findings, SARIF 2.1.0, and run metadata.

All runtime code uses the Python standard library. The model connection is restricted to localhost/loopback. RAG retrieves reference text; it does not train or fine-tune the model. The loader maps SecureGuard fields (`title`, `description`, `unsafe`, `safe`) and MITRE-style aliases (`name`, `desc`, `bad`, `good`, `lang`, `cves`) into one schema, filters examples by source language, and sends at most one top-ranked record per CWE.

## Quick demo

The bundled `samples/` folder contains four teaching examples: safer and intentionally vulnerable Python and C files. `--demo` scans those examples; it does not scan your computer or a separate project.

From this folder, scan the bundled examples with the local Ollama model:

```bash
python3 secure_audit.py --demo --model qwen2.5-coder:3b --out demo_output
```

To demonstrate static analysis and RAG without calling Ollama:

```bash
python3 secure_audit.py --demo --no-llm --out demo_output
```

Or run the demo helper:

```bash
sh demo.sh
```

Open `demo_output/report.md` to see the report. Each finding shows its source line, reason, fix guidance, and (when available) the exact CWE description and mitigation from the local knowledge base. `findings.json` contains structured findings, `findings.sarif` is for compatible code-scanning tools, and `run.json` records run/model diagnostics. The safe samples should normally have no static candidates; the vulnerable samples intentionally contain examples for the supported checks.

## Use the local LLM

Install Ollama and download a code model while internet access is available. For example:

```bash
ollama pull qwen2.5-coder:3b
```

Check that Ollama is reachable and the model is installed:

```bash
python3 secure_audit.py --doctor --model qwen2.5-coder:3b
```

After the model is on the computer, the audit can run without internet. Start Ollama, then run:

```bash
python3 secure_audit.py samples/vulnerable_app.py --model qwen2.5-coder:3b --out demo_output
```

The default endpoint is `http://localhost:11434`. The project refuses a non-loopback Ollama host so source code is not sent to a remote service. If Ollama or the selected model is unavailable, AST and RAG analysis still complete and the run metadata records that the LLM stage was unavailable. `--no-llm` disables the model stage explicitly. The report distinguishes model proposals, proposals accepted by the evidence gate, duplicates of static findings, and unique findings added by the model. A connected model can return zero proposals.

## Use chunking and semantic retrieval

The default retrieval method is BM25, which runs without Ollama in `--no-llm` mode. Select a locally installed embedding model
to index the CWE knowledge base for semantic search. For example:

```sh
ollama pull all-minilm
python3 secure_audit.py --doctor --no-llm --embedding-model all-minilm
python3 secure_audit.py --demo --no-llm --embedding-model all-minilm --out demo_embedding
```

Keep an Ollama version that supports `/api/embed` running while scanning. In this command, `--no-llm` disables generative code review.
The embedding model still runs locally. Remove `--no-llm` to also use a separately installed chat model.

For semantic retrieval, SecureGuard splits each record's description, mitigation, examples,
and keywords into chunks of up to 360 UTF-8 bytes with up to 60 bytes of overlap. It keeps
the CWE and record field with each chunk. Ollama embeds the chunks and the search query with
the same model. SecureGuard ranks chunks by cosine similarity and keeps the highest-scoring
chunk per CWE, filtered by source language. Exact CWE lookups still take priority where the
analyzer supplied an ID.

The index is built per run. `run.json` includes the model name, chunk count and vector dimensions.
Findings that use semantic retrieval record the matched passage in `findings.json` and `report.md`.
If the requested embedding model cannot run, the command reports an error. Run without
`--embedding-model` to use BM25.

## Use another local knowledge base

The `--kb` option accepts one or more JSONL files (one JSON object per line), a JSON array, or a JSON object containing a record list. You can merge the bundled notes with a larger CWE database:

```bash
python3 secure_audit.py --demo --model qwen2.5-coder:3b \\
  --kb secureguard/knowledge_base.jsonl secureguard/knowledge_base_full.jsonl \\
  --out demo_output
```

Copy the extra file to `secureguard/knowledge_base_full.jsonl`, or pass its existing path. The loader recognizes common field names, skips malformed rows, removes exact duplicates, and prefers records matching the scanned language. Python, C, C++, and language-neutral CWE records are relevant to this project. A larger knowledge base adds reference context; it does not automatically add static-analysis rules or match installed dependency versions against CVEs. Use `--rag-limit 1` through `--rag-limit 10` to change the maximum number of distinct CWE references per file; the default is 4.

## Scan your own code

```bash
python3 secure_audit.py /path/to/your_file.py --model qwen2.5-coder:3b --out audit_output
python3 secure_audit.py /path/to/your/source_project --model qwen2.5-coder:3b --out audit_output
```

Replace the example path with the real file or project folder. A directory scan includes supported source files under that directory. Supported extensions are `.py`, `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, and `.hxx`. Reports are written to `audit_output/report.md`, `audit_output/findings.json`, `audit_output/findings.sarif`, and `audit_output/run.json` unless `--out` is changed.

## Current checks

- User or request data reaching `eval()` / `exec()`
- Tainted values reaching `subprocess` with `shell=True`, `os.system()`, or `os.popen()`
- Tainted query text reaching common database `.execute()` calls
- Untrusted data passed to `pickle` or unsafe YAML loading
- Tainted values used as file paths or template source
- Credential-like variable names assigned string literals
- Disabled TLS verification (HTTP client flags, unverified SSL contexts, and explicit `CERT_NONE` / hostname-check assignments)
- Unsafe `tempfile.mktemp()` use and potentially weak hash functions
- C/C++ unsafe buffer functions (`gets`, `strcpy`, `strcat`, `sprintf`), unbounded `%s` input, shell commands, and tainted copy lengths
- Additional findings proposed by the optional local model, subject to evidence validation

## Project files

- `secureguard/analyzer.py` — Python AST analysis and language dispatch
- `secureguard/c_family.py` — C/C++ lexical source-to-sink analysis
- `secureguard/rag.py` — offline BM25 retrieval
- `secureguard/llm.py` — localhost-only Ollama client and evidence gate
- `secureguard/pipeline.py` — agent-style orchestration
- `secureguard/report.py` — Markdown and JSON reports
- `findings.sarif` — standard machine-readable SARIF output
- `secureguard/knowledge_base.jsonl` — local CWE notes and safer code patterns
- `samples/` — intentionally vulnerable and safer examples
- `docs/` — architecture and bilingual demo script
- `docs/TEAM_WORK_SPLIT.md` — parallel work suggestion for a three-person team
- `docs/PROJECT_OVERVIEW_RU.md` — Russian guide to the project, commands, and report

## Limitations

This is a classroom prototype, not a proof of safety. Python taint tracking is conservative and intraprocedural. The C/C++ adapter is lexical rather than a full compiler AST, so it may miss macro, alias, pointer, and control-flow behavior. Neither analyzer fully models sanitizers, native libraries, or arbitrary control flow. False positives and missed issues are possible. A clean report does not prove that code is secure. Review every finding and describe these limits during the presentation.
