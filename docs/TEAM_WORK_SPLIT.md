# Suggested parallel work split

The project modules have small, explicit boundaries so a three-person group can work in parallel.

| Person | Owns | Concrete deliverable |
| --- | --- | --- |
| 1 | Language analyzers | Add/refine Python AST rules in `secureguard/analyzer.py` and C/C++ checks in `secureguard/c_family.py`; maintain safe and vulnerable examples. |
| 2 | RAG knowledge base | Add reviewed CWE entries to `secureguard/knowledge_base.jsonl`; improve retrieval queries and explain why each reference is relevant. |
| 3 | Local model and presentation | Set up Ollama/model on the demo computer, refine `secureguard/llm.py` prompts and `secureguard/pipeline.py`, prepare the bilingual demo. |

## Integration contract

- Analyzer findings are dictionaries with `file`, `line`, `cwe`, `title`, `evidence`, `reason`, `recommendation`, `confidence`, and `source` fields.
- Knowledge records are one JSON object per line with `cwe`, `title`, `keywords`, `description`, `unsafe`, and `safe` fields.
- The LLM returns a JSON object with a `findings` array. The evidence gate checks a full source line or a distinctive exact code fragment against the original source before the report accepts it.
- All modules use the Python standard library; the only external runtime component is the locally installed Ollama application and model.

## Two-day order

1. First agree on the finding and knowledge-record formats above.
2. Get the CLI working in `--no-llm` mode and prepare the vulnerable example report.
3. Add or refine RAG records and confirm the demo shows a retrieved CWE explanation.
4. Connect the local model, then prepare a fallback demo that still works if Ollama is unavailable.
5. Rehearse the English/Turkish explanation and state the analyzer's limitations honestly.
