# adf-runtime-worker

Ubuntu WSL2 host CLI execution, worktrees and process supervision for ADF. This is an independent local Git repository and a pinned submodule of the ADF umbrella.

**Foundation scaffold, not a working MVP.** Read [module design](docs/development.md) for what exists and what remains. Proposed GitHub name: `adf-runtime-worker`; no GitHub remote has been created.

## Umbrella documentation

- [Architecture](../../docs/architecture.md)
- [Product and acceptance](../../docs/product.md)
- [Contracts](../../docs/contracts.md)
- [Security](../../docs/security.md)
- [Backlog](../../docs/backlog.md)
- [Local development](../../docs/local-development.md)
- [Repository publication](../../docs/repositories.md)

These relative links work inside the initialized umbrella checkout. A standalone module clone contains its own `docs/development.md`; obtain the matching umbrella release for shared docs/contracts. Published umbrella URLs can be added after the user provides actual repository locations.

## Scaffold commands

Run from this module directory (Python 3.12+; frontend Node 24 LTS / npm).

```sh
python -m pip install -e .
python -m unittest discover -s tests
adf-worker doctor
adf-worker mock --request ../../packages/contracts/examples/execution-request.json
```

Run only the host worker in WSL2 for eventual real CLI execution; it is not a Compose service. Foundation mock/probe code never launches coding agents. For Python, use a local virtual environment; install commands do not change global packages when run there. No secret is required to validate/mock the scaffold.
