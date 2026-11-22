# Prompt-injection benchmark data

The benchmark (`src/client/scripts/injection-bench.mjs`, `npm run injection:bench` in `src/client`) measures the rules-based detector on data it was not tuned on. Results are published in `docs/latest/shield360/prompt-injection.mdx`; the reports of each published run are in `results/`.

## What is here

| File | What |
| --- | --- |
| `datasets.json` | The public datasets the benchmark downloads, pinned to a revision, with licence and label mapping |
| `gen-enterprise-benign.mjs` → `enterprise-benign.json` | 175 benign samples of everyday enterprise work (code, support, documentation, operations output, business writing, security work, email, tool arguments, files, translation), written by the Shield360 maintainers for this benchmark. 55 are tagged `hard`: ordinary text that shares words with attacks ("ignore", "override", "system prompt", "act as", "admin") |
| `results/` | The JSON and Markdown report of each published run. Reports name samples by id only, never by text |
| `.cache/` | Downloaded datasets and local reports (git-ignored) |

The shared corpus (`../corpus.json`, from `../gen-corpus.mjs`) supplies the tuning split, the only data rules may be tuned on, and a small held-out split.

## Public datasets

None of these is copied into this repository. The benchmark downloads them at run time into `.cache/`, so their licences govern your local copy, not this repository. Licences were read from each dataset's page on 2026-10-14.

| Dataset | Licence | Used as | Notes |
| --- | --- | --- | --- |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 on the dataset card (its `dataset_info` block also says CC-BY-4.0) | Held out: 263 injections, 399 benign | English and German. Labels follow a broad definition: any attempt to steer the model off task counts |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | Held out: 1,000 injections | Prompts from the Gandalf game, selected by similarity to "Ignore all previous instructions" |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | Held out: 666 jailbreaks, 1,332 benign | Jailbreak persona prompts against benign prompts, many of them benign role-play |
| [databricks/databricks-dolly-15k](https://huggingface.co/datasets/databricks/databricks-dolly-15k) | CC-BY-SA-3.0 | Held out: 15,011 benign | Instructions with their reference context. Share-alike, so never redistributed here |

deepset and Gandalf are read through the Hugging Face datasets-server API, which serves each dataset's current revision; the report records the revision it got and a SHA-256 of what it read, and warns when the revision differs from the pin. The other two are downloaded from the pinned revision.

## Rules for using this data

- Tune rules on the corpus's tuning split only. Never look at held-out misses to write a rule; the benchmark prints sample text only with `--misses tuning`.
- When rules change, run the benchmark once and publish the held-out numbers before and after.
- Add benign enterprise samples by editing `gen-enterprise-benign.mjs` and running it with Node. Never paste customer data.
