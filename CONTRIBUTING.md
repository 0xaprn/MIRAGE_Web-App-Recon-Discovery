# Contributing

1. Open an issue describing the problem, expected behavior and security impact.
2. Keep changes focused; avoid adding a dependency unless the capability cannot be implemented safely and maintainably with the standard library.
3. Add tests for scope boundaries, malformed input, network failure and report safety where applicable.
4. Run `python3 -m unittest discover -s tests -v` before submitting.
5. Update README, architecture and roadmap when behavior changes.
6. Never add real credentials, target data, private reports or unredacted customer evidence.

Security-sensitive changes should explain the threat model, authorization boundary and failure behavior.
