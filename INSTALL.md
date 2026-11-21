# Installing ORDIVYR

Requirements: Python >= 3.11, Linux (tested). One runtime dependency: `cryptography`. Optional: `bubblewrap` (needed to run stdio plugins), Ollama / LM Studio for local models.

```
python3 -m venv .venv && . .venv/bin/activate
# download the wheel + SHA256SUMS from the GitHub Release, then:
sha256sum -c SHA256SUMS --ignore-missing
pip install ./ordivyr-0.5.0-py3-none-any.whl
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

## Board
```
ordivyr-board init --home ~/.ordivyr-board --model <model> --base-url http://127.0.0.1:8080/v1
ordivyr-board doctor --home ~/.ordivyr-board
ordivyr-board up --home ~/.ordivyr-board          # also runs the built-in personal worker
ordivyr-board backup --home ~/.ordivyr-board --out board.bak [--include-personal] && ordivyr-board backup-verify --from board.bak
```

`init` uses the built-in engine by default (no extra package). A loopback model is free; a remote HTTPS model is a paid endpoint and is refused until you pass `--authorize-daily-usd` and `--authorize-total-usd` to `init`. `ordivyr-board init --engine lite` selects the optional `ordivyr-lite` worker instead.

Backups never contain `master.key`; store it separately (see `docs/board/OPERATIONS.md`). `backup --include-personal` also saves the owner/worker tokens and model config (including the API key), which is what a restored personal install needs to run, so protect that backup like those secrets.
