# Synthetic checkout repository

This repository is deliberately small and contains no customer data. Its checkout function has one known bug: a percentage discount is added to the subtotal instead of subtracted.

Run the tests from this directory with:

```powershell
python -m pytest -q tests
```

The baseline is expected to contain one failing regression test. This fixture is synthetic test input; it is not Switch evidence or an agent-generated patch.
