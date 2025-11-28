# Wazuh Rules as Code (RaC)

This repository manages custom Wazuh detection rules and decoders using a local-first deployment approach.

## Workflow
1. Develop rules locally in `rules/` and `decoders/`
2. Validate using `./scripts/validate.sh`
3. Deploy locally using `./scripts/deploy.sh`
4. Push to GitHub after successful deployment

## Directory Structure
- `rules/` - Custom detection rules (100000-120000 ID range)
- `decoders/` - Custom decoders
- `scripts/` - Deployment and validation scripts
- `docs/` - Documentation
