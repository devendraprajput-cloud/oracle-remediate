# Knowledge base for the documentation context (RAG)

The notes in this folder are short, original explanations written for this
project so that the retrieval path works out of the box. They are not a
substitute for the paper's corpus, which is:

* the CIS Oracle Database 19c Benchmark v2.0.0 (licensed by CIS),
* the Oracle Database Security Guide,
* relevant My Oracle Support notes (requires a support contract).

Add your own licensed copies as `.md` or `.txt` files and run
`orarem rag ingest <dir>`. Start a file with `controls: <id>, <id>` to tag its
chunks with catalog control ids. Do not commit licensed content to a public
repository.
