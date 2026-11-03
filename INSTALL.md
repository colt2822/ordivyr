# Installing ORDIVYR

Requirements: Python >= 3.10, Linux (tested). No runtime dependencies. Optional: `bubblewrap` (needed to run stdio plugins), Ollama / LM Studio for local models.

```
python3 -m venv .venv && . .venv/bin/activate
pip install ordivyr-0.4.0a0.tar.gz        # verify first:  sha256sum -c SHA256SUMS
ordivyr doctor                            # checks Python, bwrap, GPU, backends
ordivyr hw                                # detected hardware
ordivyr templates                         # which teams this machine can run
ordivyr new local-dev-duo -o board.json
ordivyr run board.json --mission "add input validation to the signup form"
```

## Local models
Start Ollama (`ollama serve`, pull a model) or LM Studio's server; `ordivyr hw` and `ordivyr doctor` will list what they find. Paid/BYOK providers are only called when you configure a key and allow spending.

## Plugins
```
ordivyr plugin install <folder-or-archive>
ordivyr plugin inspect <id>          # shows permissions and tree hash
ordivyr plugin trust <id> <hash>     # required for native plugins
ordivyr plugin enable <id>
ordivyr plugin call <id> <tool> '{"json": "args"}'
```
See `ordivyr/docs/PLUGINS.md`; a working example is in `ordivyr/examples/plugins/shout-native`.

## Verify, uninstall
`python -m pytest` (from a source checkout) runs the suite offline. `pip uninstall ordivyr` removes it; plugin state lives under the `--home` directory you chose.
