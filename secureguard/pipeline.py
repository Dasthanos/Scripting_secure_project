"""Agent-style pipeline: AST analyzer -> local RAG -> local LLM -> evidence gate -> reports."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .analyzer import analyze_file
from .embeddings import OllamaEmbedder
from .llm import LocalModelError, OllamaAuditor, validate_model_findings
from .rag import LocalRAG, language_for_path
from .report import write


SKIP_DIRS = {
    ".git", ".idea", ".vscode", ".venv", "venv", "__pycache__", "node_modules", "build", "dist",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "audit_output",
}
SOURCE_EXTENSIONS = {".py", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"}


def source_files(path: Path) -> list[Path]:
    if path.is_file():
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            raise ValueError("Supported source types are Python (.py) and C/C++ (.c, .h, .cpp, .hpp, .cc, .cxx, .hxx).")
        return [path]
    files = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS
                   and not any(part in SKIP_DIRS for part in p.parts))
    if not files:
        raise ValueError(f"No supported Python or C/C++ source files found under: {path}")
    return files


def run(path: Path, out_dir: Path, kb_path: Path | list[Path], model_name: str | None,
        host: str, timeout: int, log=print, rag_limit: int = 4,
        embedding_model: str | None = None) -> list[dict[str, Any]]:
    start = time.time()
    files = source_files(path)
    rag = LocalRAG.from_files(kb_path if isinstance(kb_path, list) else [kb_path])
    embedding_chunks = 0
    if embedding_model:
        log(f"[RAG] Indexing knowledge-base chunks with {embedding_model}")
        embedding_chunks = rag.index_embeddings(OllamaEmbedder(embedding_model, host, timeout))
        log(f"[RAG] Indexed {embedding_chunks} chunks ({rag.embedder.dimensions} dimensions)")
    model = OllamaAuditor(model_name, host=host, timeout=timeout) if model_name else None
    findings: list[dict[str, Any]] = []
    llm_status = "disabled" if model is None else "ready"
    llm_error = ""
    model_metrics: dict[str, Any] = {
        "proposed": 0, "accepted": 0, "rejected": 0, "requests": 0,
        "duplicates_of_static": 0, "duplicate_model_proposals": 0, "unique_additions": 0,
        "rejection_reasons": {}, "evidence_match_modes": {},
    }
    rag_retrievals = 0
    exact_cwe_references = 0
    missing_cwe_references = 0
    rag_stats = rag.load_stats
    log(f"[RAG base] {rag_stats['loaded_records']} usable record(s), "
        f"{rag_stats['unique_cwes']} unique CWE(s), "
        f"{rag_stats['invalid_records']} invalid row(s) skipped, "
        f"{rag_stats['duplicates_removed']} exact duplicate(s) removed")
    for index, file in enumerate(files, 1):
        log(f"[Source analysis {index}/{len(files)}] {file} ({file.suffix.lower()})")
        source, static_findings = analyze_file(file)
        file_language = language_for_path(file)
        log(f"  static candidates: {len(static_findings)}")
        # Retrieval enriches both static findings and the optional whole-file LLM review.
        file_refs = rag.search(source, limit=rag_limit, lang=file_language)
        rag_retrievals += len(file_refs)
        for item in static_findings:
            exact_ref = rag.lookup_cwe(item.get("cwe", ""), lang=file_language)
            refs = [exact_ref] if exact_ref else rag.search(
                item.get("cwe", "") + " " + item.get("title", "") + " " + item.get("evidence", ""),
                limit=1, lang=file_language)
            item["references"] = refs
            if exact_ref:
                exact_cwe_references += 1
                mitigation = str(exact_ref.get("mitigation", "")).strip()
                if mitigation:
                    item["recommendation"] = mitigation[:800]
            else:
                missing_cwe_references += 1
            findings.append(item)
        if model is not None and not llm_error:
            try:
                log("  local LLM auditor: reviewing source with retrieved references")
                preferred_cwes = [item.get("cwe", "") for item in static_findings]
                retrieved = rag.context(source, limit=rag_limit, lang=file_language,
                                        preferred_cwes=preferred_cwes, search_hits=file_refs)
                model_rows = model.audit(source, str(file), retrieved, static_findings)
                model_metrics["requests"] += model.last_audit_chunks
                gate: dict[str, Any] = {}
                validated = validate_model_findings(model_rows, source, str(file), diagnostics=gate)
                model_metrics["proposed"] += gate["proposed"]
                model_metrics["accepted"] += gate["accepted"]
                model_metrics["rejected"] += gate["rejected"]
                for reason, count in gate["rejection_reasons"].items():
                    model_metrics["rejection_reasons"][reason] = (
                        model_metrics["rejection_reasons"].get(reason, 0) + count)
                for mode, count in gate["evidence_match_modes"].items():
                    model_metrics["evidence_match_modes"][mode] = (
                        model_metrics["evidence_match_modes"].get(mode, 0) + count)
                if gate["proposed"] == 0:
                    log("  model returned 0 candidate findings")
                else:
                    rejected = ", ".join(f"{name}={count}" for name, count in gate["rejection_reasons"].items())
                    detail = f"; rejected: {rejected}" if rejected else ""
                    modes = ", ".join(f"{name}={count}" for name, count in gate["evidence_match_modes"].items())
                    mode_detail = f"; evidence matched: {modes}" if modes else ""
                    log(f"  model proposed {gate['proposed']}; evidence gate accepted {gate['accepted']}"
                        f"{mode_detail}{detail}")
                static_keys = {(item.get("file", ""), int(item.get("line", 0)), item.get("cwe", ""))
                               for item in static_findings}
                model_keys: set[tuple[str, int, str]] = set()
                for item in validated:
                    key = (item.get("file", ""), int(item.get("line", 0)), item.get("cwe", ""))
                    exact_ref = rag.lookup_cwe(item.get("cwe", ""), lang=file_language)
                    item["references"] = [exact_ref] if exact_ref else rag.search(
                        item["cwe"] + " " + item["title"] + " " + item["evidence"],
                        limit=1, lang=file_language)
                    if key in static_keys:
                        model_metrics["duplicates_of_static"] += 1
                        continue
                    if key in model_keys:
                        model_metrics["duplicate_model_proposals"] += 1
                        continue
                    model_keys.add(key)
                    if exact_ref:
                        exact_cwe_references += 1
                    else:
                        missing_cwe_references += 1
                    model_metrics["unique_additions"] += 1
                    findings.append(item)
            except LocalModelError as exc:
                model_metrics["requests"] += model.last_audit_chunks
                llm_error = str(exc)
                llm_status = "unavailable; static analysis continued"
                log(f"  local LLM unavailable: {exc}")
        if file_refs:
            log(f"  RAG retrieved {len(file_refs)} local document(s)")

    # Deduplicate equivalent findings from the two analysis agents.
    unique: dict[tuple[str, int, str], dict[str, Any]] = {}
    for item in findings:
        key = (item.get("file", ""), int(item.get("line", 0)), item.get("cwe", ""))
        if key not in unique or item.get("source") == "static-analysis":
            unique[key] = item
    findings = sorted(unique.values(), key=lambda x: (x.get("file", ""), x.get("line", 0), x.get("cwe", "")))
    metadata = {
        "files_scanned": len(files), "findings": len(findings), "model": model_name or "disabled",
        "llm_status": llm_status, "llm_error": llm_error,
        "model_metrics": model_metrics,
        "rag_knowledge_base_documents": len(rag.records),
        "rag_base": rag_stats,
        "rag_search_method": "embedding" if embedding_model else "bm25",
        "rag_embedding_model": embedding_model,
        "rag_embedding_chunks": embedding_chunks,
        "rag_embedding_dimensions": rag.embedder.dimensions if rag.embedder else 0,
        "rag_retrieval_limit_per_file": rag_limit,
        "rag_retrievals": rag_retrievals,
        "exact_cwe_references": exact_cwe_references,
        "missing_cwe_references": missing_cwe_references,
        "elapsed_seconds": round(time.time() - start, 2),
        "pipeline": ["Python AST + C/C++ source-to-sink analyzers",
                     "local embedding RAG" if embedding_model else "local BM25 RAG",
                     "local Ollama auditor (optional)",
                     "exact-evidence validation", "JSON/Markdown reporter"],
    }
    write(findings, metadata, out_dir)
    summary = f"Summary: {len(files)} file(s), {len(findings)} finding(s)"
    if model is None:
        log(summary + "; local model disabled.")
    else:
        log(summary + f"; local model proposed {model_metrics['proposed']}, "
            f"evidence-checked {model_metrics['accepted']}, rejected {model_metrics['rejected']}; "
            f"added {model_metrics['unique_additions']} unique model-only finding(s), "
            f"{model_metrics['duplicates_of_static']} duplicate(s) matched static findings.")
    log(f"CWE references: {exact_cwe_references} exact match(es), "
        f"{missing_cwe_references} CWE(s) absent from the loaded knowledge base.")
    log(f"Done: {len(findings)} finding(s). Reports written to {out_dir}")
    return findings
