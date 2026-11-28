"""Command line interface."""
from __future__ import annotations

import argparse
from pathlib import Path

from .llm import LocalModelError, OllamaAuditor
from .pipeline import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secureguard",
        description="Offline Python and C/C++ secure-coding auditor with local RAG and Ollama",
        epilog=("Examples:\n"
                "  python3 secure_audit.py --demo --model qwen2.5-coder:3b\n"
                "  python3 secure_audit.py /path/to/app.py --model qwen2.5-coder:3b\n"
                "  python3 secure_audit.py /path/to/project --no-llm"),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", nargs="?", type=Path, help="Python/C/C++ source file or directory to scan")
    parser.add_argument("--demo", action="store_true", help="scan the bundled safe and vulnerable sample files")
    parser.add_argument("--out", type=Path, default=Path("audit_output"), help="report output directory")
    parser.add_argument("--kb", type=Path, nargs="+",
                        default=[Path(__file__).with_name("knowledge_base.jsonl")],
                        help="one or more offline JSONL/JSON CWE knowledge bases to merge")
    parser.add_argument("--rag-limit", type=int, default=4,
                        help="maximum distinct CWE references retrieved per source file (1-10)")
    parser.add_argument("--model", default="qwen2.5-coder:3b", help="installed local Ollama model")
    parser.add_argument("--embedding-model", help="local Ollama model for chunk-based semantic retrieval")
    parser.add_argument("--host", default="http://localhost:11434", help="local Ollama endpoint")
    parser.add_argument("--timeout", type=int, default=180, help="local model request timeout in seconds")
    parser.add_argument("--no-llm", action="store_true", help="disable Ollama code review; an explicitly selected embedding model can still run")
    parser.add_argument("--doctor", action="store_true", help="check local Ollama and whether the selected model is installed")
    args = parser.parse_args(argv)
    if args.doctor:
        try:
            models = OllamaAuditor(args.model, host=args.host, timeout=args.timeout).available_models()
        except LocalModelError as exc:
            parser.error(str(exc))
        print(f"Ollama is available at {args.host}.")
        print("Installed models: " + (", ".join(models) if models else "none"))
        selected_models = []
        if not args.no_llm or not args.embedding_model:
            selected_models.append(args.model)
        if args.embedding_model:
            selected_models.append(args.embedding_model)
        for selected in selected_models:
            if selected not in models and f"{selected}:latest" not in models:
                print(f"Selected model is missing: {selected}")
                return 1
            print(f"Selected model is installed: {selected}")
        return 0
    if args.demo and args.path is not None:
        parser.error("use either --demo or a source path, not both")
    scan_path = args.path
    if args.demo:
        scan_path = Path(__file__).resolve().parent.parent / "samples"
        print("Demo mode: scanning the project's bundled safe and vulnerable examples.")
    if scan_path is None:
        parser.error("provide a source path, use --demo, or use --doctor")
    if not scan_path.exists():
        parser.error(f"path does not exist: {scan_path}")
    missing_kbs = [str(kb) for kb in args.kb if not kb.exists()]
    if missing_kbs:
        parser.error("knowledge base file(s) do not exist: " + ", ".join(missing_kbs))
    if not 1 <= args.rag_limit <= 10:
        parser.error("--rag-limit must be between 1 and 10")
    try:
        run(scan_path, args.out, args.kb, None if args.no_llm else args.model,
            args.host, args.timeout, rag_limit=args.rag_limit, embedding_model=args.embedding_model)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 0
