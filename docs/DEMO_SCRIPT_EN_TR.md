# Short presentation script

## English

Hello. Our project is SecureGuard, an offline secure-coding auditor for Python and C/C++. The Python analyzer uses the built-in AST module; the C/C++ analyzer checks common input-to-sink flows and unsafe memory APIs. The RAG agent retrieves CWE guidance from a local knowledge base. An optional local Ollama model reviews the code and retrieved references. An evidence gate rejects model findings unless the quoted line exists exactly in the source. Finally, the program writes Markdown and JSON reports. We will show vulnerable Python and C examples and compare them with safer patterns. The tool reports candidates for review; it does not claim that every vulnerability can be found.

## Türkçe

Merhaba. Projemizin adı SecureGuard. Python ve C/C++ kodunu çevrimdışı inceleyen bir güvenli kodlama aracıdır. Python analizörü yerleşik AST modülünü kullanır; C/C++ analizörü yaygın girdi-tehlikeli işlem akışlarını ve güvensiz bellek fonksiyonlarını kontrol eder. RAG ajanı, yerel bilgi tabanından CWE açıklamalarını ve güvenli örnekleri bulur. İsteğe bağlı yerel Ollama modeli kodu ve bulunan kaynakları inceler. Kanıt doğrulama aşaması, modelin belirttiği satır kaynak kodda birebir yoksa bulguyu reddeder. Son olarak Markdown ve JSON raporları oluşturulur. Kasıtlı olarak güvenli olmayan Python ve C örneklerini, daha güvenli yaklaşımlarla karşılaştıracağız. Araç inceleme için olası bulgular üretir; tüm açıklıkları bulduğunu iddia etmez.

## Demo commands

The easiest presentation command scans the four safe and intentionally vulnerable examples included in `samples/`:

```bash
python3 secure_audit.py --demo --model qwen2.5-coder:3b --out demo_output
```

It does not scan a separate user project. To scan your own source, pass its path instead of `--demo`.

Static analysis plus local RAG, without a model:

```bash
python3 secure_audit.py samples/vulnerable_app.py --no-llm --out demo_output
python3 secure_audit.py samples/vulnerable_app.c --no-llm --out demo_output
```

With a locally installed Ollama model:

```bash
python3 secure_audit.py samples/vulnerable_app.py --model qwen2.5-coder:3b --out demo_output
python3 secure_audit.py samples/vulnerable_app.c --model qwen2.5-coder:3b --out demo_output
```
