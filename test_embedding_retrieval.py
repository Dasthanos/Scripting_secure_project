from collections import Counter
from contextlib import contextmanager, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from secureguard.cli import main
from secureguard.embeddings import OllamaEmbedder, text_chunks
from secureguard.llm import LocalModelError


@contextmanager
def embedding_server(respond):
    """Exercise the local HTTP protocol with deterministic test vectors."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, request))
            status, data = respond(self.path, request)
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            worker.join()


class EmbeddingRetrievalTests(unittest.TestCase):
    def test_chunks_cover_long_text_and_preserve_overlap(self):
        source = "0123456789" * 6
        chunks = text_chunks(source, size=20, overlap=5)
        self.assertTrue(all(0 < len(chunk) <= 20 for chunk in chunks))
        self.assertEqual(chunks[0] + "".join(chunk[5:] for chunk in chunks[1:]), source)
        for earlier, later in zip(chunks, chunks[1:]):
            self.assertEqual(earlier[-5:], later[:5])
        self.assertEqual(text_chunks("   "), [])
        with self.assertRaises(ValueError):
            text_chunks(source, size=5, overlap=5)

    def test_chunks_bound_utf8_and_token_dense_text(self):
        source = "a." * 650 + "🐍çğ" * 150
        chunks = text_chunks(source, overlap=0)
        self.assertGreater(len(chunks), 1)
        self.assertEqual("".join(chunks), source)
        self.assertTrue(all(len(chunk.encode("utf-8")) <= 360 for chunk in chunks))

    def test_ollama_batches_and_validates_dimensions(self):
        def respond(_path, request):
            size = 2 if len(request["input"]) == 32 else 3
            return 200, {"embeddings": [[1] * size for _ in request["input"]]}

        with embedding_server(respond) as (host, requests):
            embedder = OllamaEmbedder("test-model", host, 5)
            with self.assertRaisesRegex(LocalModelError, "inconsistent embedding dimensions"):
                embedder.embed(["one"] * 33)
        self.assertEqual([len(item["input"]) for _, item in requests], [32, 1])

    def test_semantic_match_selects_the_passage_and_reaches_the_review_prompt(self):
        def respond(path, request):
            if path == "/api/chat":
                return 200, {"message": {"content": '{"findings": []}'}}
            vectors = [
                [0, 1] if "CWE-90" in text or
                ("CWE-378" in text and "text for semantic matching" not in text) else [1, 0]
                for text in request["input"]
            ]
            return 200, {"embeddings": vectors}

        with TemporaryDirectory() as directory, embedding_server(respond) as (host, requests):
            root = Path(directory)
            source = root / "example.py"
            source.write_text("import tempfile\npath = tempfile.mktemp()\n", encoding="utf-8")
            kb = root / "kb.json"
            kb.write_text(json.dumps([
                {"cwe": "CWE-90", "description": "unrelated " * 160, "keywords": ["mktemp"]},
                {"cwe": "CWE-378", "lang": "python",
                 "description": "unrelated " * 120 + "text for semantic matching",
                 "mitigation": "unrelated recommendation"},
                {"cwe": "CWE-379", "lang": "java", "description": "ignore other languages"},
            ]), encoding="utf-8")
            out = root / "report"

            self.assertEqual(main([str(source), "--kb", str(kb), "--host", host,
                                   "--embedding-model", "test-model", "--rag-limit", "1",
                                   "--out", str(out)]), 0)

            finding, = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            reference, = finding["references"]
            self.assertEqual(finding["cwe"], "CWE-367")
            self.assertEqual(reference["cwe"], "CWE-378")
            self.assertEqual(reference["retrieval_method"], "embedding")
            self.assertGreater(reference["matched_chunk"]["number"], 1)
            self.assertIn("text for semantic matching", reference["matched_chunk"]["text"])
            run = json.loads((out / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(run["rag_embedding_dimensions"], 2)
            self.assertGreater(run["rag_embedding_chunks"], 3)
            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("Embedding similarity", report)
            self.assertIn("text for semantic matching", report)
            self.assertIn("Indexed knowledge-base chunks", report)

        self.assertEqual(Counter(path for path, _ in requests), {"/api/embed": 3, "/api/chat": 1})
        embeddings = [request for path, request in requests if path == "/api/embed"]
        self.assertTrue(all(request["model"] == "test-model" for request in embeddings))
        self.assertTrue(all(request["truncate"] is False for request in embeddings))
        chat, = [request for path, request in requests if path == "/api/chat"]
        self.assertIn("Retrieved description:", chat["messages"][1]["content"])
        self.assertNotIn("CWE-90", chat["messages"][1]["content"])

    def test_unavailable_requested_model_fails_clearly(self):
        with TemporaryDirectory() as directory, embedding_server(
                lambda _path, _request: (404, {})) as (host, _):
            root = Path(directory)
            source = root / "input.py"
            source.write_text("print('hello')\n", encoding="utf-8")
            kb = root / "kb.json"
            kb.write_text('[{"cwe": "CWE-90"}]', encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                main([str(source), "--kb", str(kb), "--no-llm", "--host", host,
                      "--embedding-model", "missing-model", "--out", str(root / "out")])
            self.assertEqual(error.exception.code, 2)
            self.assertIn("HTTP 404 for missing-model", stderr.getvalue())
            self.assertFalse((root / "out" / "run.json").exists())


if __name__ == "__main__":
    unittest.main()
