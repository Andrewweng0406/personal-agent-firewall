# Contributing

1. Fork the repository and create a focused branch.
2. Install Python dependencies from `requirements.lock` and desktop dependencies
   with `npm ci` inside `desktop/`.
3. Keep privacy fixtures synthetic. Never commit credentials, personal data,
   private transcripts, audit databases, or `.env` files.
4. Run `python -m pytest -q` and `npm run check` from `desktop/`.
5. Open a pull request explaining behavior changes, security implications, and
   how the change was tested.

Changes to enforcement, authentication, redaction, or hook fail-open/fail-closed
behavior should include tests for both allowed and denied paths.
