# Four-repository architecture

AIOS is the final system. The other three repositories are independent implementation subsets/substrates that can be absorbed behind stable AIOS boundaries.

## Direction

```text
                         AIOS
              Authority / Control Plane
                         |
              +----------+----------+
              |                     |
          Governing rules       Execution boundary
              |                     |
      Contract / Permit /      RuntimeAdapter
      Capability / Evidence         |
      Verify / Gate / Terminal     +----+----+----+
                                   |    |    |    |
                                  try   R2   R3  external providers
```

The repositories remain independently buildable and testable. Independence does not mean equal architectural status: AIOS is the destination; the other repositories are reusable execution substrates/capability subsets.

## Absorption rule

1. Discover a useful primitive in a child repository.
2. Define the minimal AIOS contract/boundary around it.
3. Integrate or reimplement the primitive inside AIOS when it is mature enough.
4. Keep the original repository usable as an optional provider/substrate.
5. Delete duplicated AIOS machinery when an external substrate is demonstrably better.

## Non-negotiable authority boundary

External agents may Observe, Decide/Plan, Act, Verify locally, Persist and Resume within granted capability. They may not modify AIOS governing policy, evidence requirements, promotion criteria, evaluator, security controls, or terminal conditions.

AIOS remains fail-closed on contract, permit, capability, effect, receipt, evidence, verification, gate and terminal decisions.
