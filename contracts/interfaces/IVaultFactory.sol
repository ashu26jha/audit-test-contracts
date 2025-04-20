// SPDX-License-Identifier: gpl-3.0
pragma solidity ^0.8.0;
pragma abicoder v2;

interface IVaultFactory {
    event NewVault(address vaultAddress, uint256 indexed vaultId);

    function vaults(uint256 vaultId) external view returns (address);

    function isRegistered(address vault) external view returns (bool);
}
