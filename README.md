# Mightyfi Contracts

Mighty Finance is a DeFi platform designed for concentrated liquidity market making (CLMM) with leveraged positions.
It enables users to open leveraged positions, maximizing capital efficiency.

## Contracts Structure

```
├── AddressRegistry.sol
├── IndividualPosition.sol
├── MightyTimelockController.sol ## multisig, timelock
├── PaymentsUpgradeable.sol
├── PrimaryPriceOracle.sol
├── VaultRegistry.sol
├── lendingpool
├── interfaces
├── libraries
├── mock   ## Mock Contracts for testing
├── shadow ## Shadow range (uni-v3) leverage vault and implementaion
├── swapx  ## In Development
└── viewer ## Viewer contract using from front-end
```

### Core contracts

| Contract Name              | Description                                                                                                                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AddressRegistry`          | A central registry that stores the addresses of key contracts within the protocol for easy reference and access.                                                                            |
| `IndividualPosition`       | A user-specific position contract created by the Vault. Managed via proxy pattern, with its logic delegated to a separate implementation contract.                                          |
| `MightyTimelockController` | A governance contract managing permissions for proxy upgrades and critical protocol settings. Based on OpenZeppelin's `TimelockController`, supporting multisig and timelock functionality. |
| `PaymentsUpgradeable`      | A utility contract that standardizes and unifies token transfers (both ERC20 and native tokens like ETH) using `transfer` and `transferFrom`.                                               |
| `PrimaryPriceOracle`       | The main oracle contract that provides price feeds for the protocol’s internal calculations.                                                                                                |
| `VaultRegistry`            | A registry contract that manages and tracks Vault IDs. Vaults must be registered after deployment to be recognized by the protocol.                                                         |
| `LendingPool`              | A forked version of ExtraFi’s lending pool, designed to accept deposits of a single token. Vault contracts can borrow from it to create leveraged positions.                                |
