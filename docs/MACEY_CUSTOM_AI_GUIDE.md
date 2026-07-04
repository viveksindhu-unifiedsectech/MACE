# Macey — Building Your Own Proprietary AI Agent

*Straight answer to "can we make Macey our own unique AI, not just open source?"*

## The honest feasibility answer

**Yes — and you're closer than you think — but not by training a foundation
model from scratch.** Here's the reality, tier by tier:

| Option | Feasible for you? | Why |
|---|---|---|
| **Train a foundation LLM from scratch** (a new GPT/Claude) | ❌ No | Tens of millions of dollars, a large research team, months of GPU-cluster time, and enormous datasets. No early-stage company should do this. |
| **Fine-tune an open base on your private data** (LoRA) | ✅ Yes | Take Llama/Mistral/Qwen and train it on MACE's own corpus. The base is open; **your training data and the resulting weights are your IP.** Days of work, hundreds–low-thousands of dollars. This is what real vertical-AI companies do. |
| **RAG over your proprietary index** | ✅ Yes, today | Ground answers in MACE's own data (patents, playbooks, incidents, the correlation index). Makes answers unique to your platform with no training at all. |
| **Proprietary agent scaffolding** | ✅ **Already done** | Macey's tools, persona, safeguards, offline responder, and the MaceyLM backend are *your* code — not open source. |

**The key insight:** the moat is **not** the base model — everyone can get the
same open weights. The moat is (1) the private data you fine-tune on, (2) the
tool suite over MACE's proprietary engines (UTAG/CDCS/UREA, Secure Files,
conflict detection), and (3) the safeguards and grounding. You already own all
three. Fine-tuning is what makes the *model itself* also yours.

So: **Macey is already a unique, proprietary agent.** Making the underlying
*model* proprietary too is a fine-tune, not a moonshot.

## What "MaceyLM" is (already wired into the code)

Macey now has a first-class **self-hosted backend** called MaceyLM
(`agent/macey/agent.py`). Point it at any OpenAI-compatible server you run
yourself (vLLM, Ollama, LM Studio, TGI) and the model + all data stay on your
infrastructure — nothing goes to a third party:

```
MACEY_PROVIDER=maceylm
MACEYLM_BASE_URL=http://your-gpu-box:8000/v1
MACEY_MODEL=mace-security-1        # your fine-tuned model name
```

With nothing configured, Macey uses a deterministic offline responder; set
`ANTHROPIC_API_KEY` to use Claude Fable 5 as the high-capability hosted option.
MaceyLM wins automatically when `MACEYLM_BASE_URL` is set.

## The realistic path to a proprietary Macey model (4 steps)

1. **Assemble your private dataset.** Run
   `agent/macey/training/build_dataset.py` — it seeds an instruction-tuning file
   from Macey's persona, tool schemas, and curated security Q&A. Then **add your
   real, proprietary material**: analyst chat transcripts, SOAR playbooks, past
   incident write-ups, your patents, and Secure-Files scenarios. This corpus is
   the thing competitors can't copy.
2. **Pick an open base + fine-tune with LoRA.** Llama 3.1 8B or Mistral 7B are
   good starts. Use Unsloth, Axolotl, or HF PEFT on a single A100/H100 (rentable
   by the hour). LoRA keeps it cheap and fast; you get a small adapter that
   encodes MACE's voice and knowledge.
3. **Serve it.** Run the fine-tuned model behind vLLM (OpenAI-compatible) on your
   own box or a private cloud GPU. Point `MACEYLM_BASE_URL` at it.
4. **Ground it with RAG (optional but powerful).** Retrieve from your own index
   at query time so answers cite live MACE data, not just training memory.

## Rough cost & effort

| Item | Cost | Time |
|---|---|---|
| Dataset assembly | your time | days–weeks (ongoing) |
| LoRA fine-tune (7–8B) | ~$50–500 in GPU rental | hours per run |
| Inference server (one GPU) | ~$1–3/hr rented, or a bought GPU | continuous |
| RAG index | negligible | days |

That's it — a genuinely custom, self-hosted, proprietary Macey for the price of
a laptop, not a data center.

## What I need from you to take it further

- Confirm the base model preference (Llama / Mistral / Qwen), or let me pick.
- A pointer to any real transcripts/playbooks/incidents you're willing to train
  on (they stay local; nothing is sent anywhere).
- Whether you'll host inference yourself (GPU box) or rent (e.g. a private cloud
  GPU) — I'll tailor the serving config.

Give me those and I'll produce the fine-tune config and the exact serving
commands.

## One honest caveat

A fine-tuned 7–8B model is excellent for MACE's grounded, tool-driven tasks, but
it will not match a frontier hosted model on the hardest open-ended reasoning.
The best setup is usually **both**: MaceyLM for private/air-gapped and routine
work, with an option to escalate to Claude Fable 5 for the hardest questions.
Macey already supports switching between them per deployment.
