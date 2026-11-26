# Local LLM weights for ai01, fetched declaratively so the container never
# needs internet access. Hash is the file's sha256 from Hugging Face (LFS).
{ pkgs }:

{
  qwen25-3b-instruct = {
    name = "lab-qwen2.5-3b";
    # sha256 of the GGUF (hex); Ollama stores the blob as sha256-<this>.
    # Provenance: Qwen/Qwen2.5-3B-Instruct-GGUF on Hugging Face (official Qwen
    # repo). License: Qwen Research License (non-commercial), which matches
    # this repo's PolyForm Noncommercial terms.
    sha256 = "626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d";
    gguf = pkgs.fetchurl {
      url = "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf";
      hash = "sha256-YmtKZni4ZEIkDjPfgZ4AEy07p93f4c3E+7GOCpYVxi0=";
    };
  };
}
