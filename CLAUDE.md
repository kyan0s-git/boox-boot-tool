# Project notes

## Commit authorship

Commits in this repository are authored by:

```
cyyanide_ <91159868+kyan0s-git@users.noreply.github.com>
```

Use that identity for both author and committer. Do not substitute any other
person's name or email.

**The `github-commit-authorship` skill does not apply here.** That skill
mandates a different primary author; it was applied earlier in this project's
history and the resulting commits had to be rewritten to remove the wrong name.
`.claude/settings.json` turns the skill off for this repository (hidden from the
model via `skillOverrides`, and denied via a permission rule), but the rule is
written here as well so the reason survives even if the settings file is not
loaded.

Keep the Claude co-author trailer on Claude-authored commits:

```
Co-authored-by: Claude Opus 5 <noreply@anthropic.com>
```

## Testing

```bash
python3 -m pytest tests/ -q      # 127 tests, no hardware needed
python3 -m pyflakes boox tests
```

The whole suite runs against a simulated device (`boox/transport/mock.py`), so
nothing here touches real hardware. See SAFETY.md before running anything
against an actual tablet.
