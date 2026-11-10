# Contributing

Thank you for helping. venenum is deliberately small: a change should keep it a thin, predictable layer in front of ClamAV.

## Set up

```sh
corepack enable          # pnpm at the version in package.json
pnpm install
pnpm test                # no ClamAV needed: the tests use a fake clamd and a local file server
```

Use pnpm only (not npm or yarn). The service is TypeScript that Node 24 runs directly (`node src/main.ts`); keep to erasable syntax (no enums, no parameter properties), which `tsc` enforces.

## Before you open a pull request

```sh
pnpm lint                # Biome
pnpm type-check          # tsc --noEmit
pnpm test                # vitest
docker build -t venenum .
```

CI runs the same, then starts `compose.yaml` with the official ClamAV image and runs `scripts/smoke.ts` (an EICAR test string must come back infected, a clean file clean). To run that locally:

```sh
export SMOKE_KEY=$(openssl rand -hex 32)
docker compose -f compose.yaml -f compose.smoke.yaml up -d --build --wait
VENENUM_CALLER=smoke VENENUM_KEY=$SMOKE_KEY SMOKE_FIXTURE_HOST=host.docker.internal pnpm smoke
docker compose down -v
```

- Never commit the EICAR string as a file: tests and the smoke script assemble it at run time.
- A change to request signing must keep the test vector in `docs/signing.md` valid, or bump the scheme version (`v2=`) and document both.
- New behaviour comes with a test; a new setting comes with a default, a line in the README's Configuration table and in `.env.example`.
- Add a line under "Unreleased" in `CHANGELOG.md`.

## Proposing a change

Open an issue first for anything larger than a fix. Security problems go through private reporting ([SECURITY.md](SECURITY.md)), not issues.

By contributing you agree that your contribution is licensed under the MIT License of this repository.
