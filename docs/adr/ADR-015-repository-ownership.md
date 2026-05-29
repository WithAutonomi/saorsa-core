# ADR-015: Repository Ownership under WithAutonomi

## Status

Accepted (2026-05-29)

## Context

`saorsa-core` began under Saorsa Labs alongside other Saorsa foundation crates. As Autonomi v2 matured, `saorsa-core` became operationally tied to the Autonomi release train: networking, DHT, routing, trust signals, bootstrap behaviour, and integration work are reviewed and released with the WithAutonomi repositories.

Keeping this repository under `saorsa-labs` made operational monitoring ambiguous because x0x/foundation work and Autonomi delivery activity appeared in the same organisation-level feeds.

## Decision

Host `saorsa-core` in the `WithAutonomi` GitHub organisation. The repository remains named `saorsa-core`, but its location reflects Autonomi v2 release ownership and monitoring responsibility.

The ownership boundary is:

- `WithAutonomi`: Autonomi-specific implementation crates and crates that participate in the Autonomi release train.
- `saorsa-labs`: x0x repositories and foundation/shared crates such as generic crypto or messaging primitives unless their release ownership changes.

GitHub redirects from the previous location are expected to remain in place, but repository metadata, documentation, CI links, and release references should use `https://github.com/WithAutonomi/saorsa-core`.

## Consequences

### Positive

- Autonomi v2 monitoring can track `saorsa-core` together with the `ant-*` repositories.
- x0x and foundation monitoring is less noisy.
- Release ownership is clearer for maintainers and external contributors.
- Repository metadata and badges point at the canonical organisation.

### Negative

- Existing local clones may need their `origin` URL updated.
- Any external automation that hard-codes the previous URL must be updated.

### Neutral

- The crate name does not change.
- Downstream dependencies continue to use the published crate name/version.
- GitHub redirects should preserve most existing links during the transition.

## Alternatives Considered

1. **Keep the repository in `saorsa-labs`**
   - Rejected because operational activity would continue to blur x0x/foundation monitoring with Autonomi v2 release work.

2. **Rename the crate/repository to remove the `saorsa-` prefix**
   - Rejected because the crate name is already established and the move is about ownership/operations, not API or brand churn.

## References

- Canonical repository: <https://github.com/WithAutonomi/saorsa-core>
- Related transport crate: <https://github.com/WithAutonomi/saorsa-transport>
