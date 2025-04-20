// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma abicoder v2;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./interfaces/IAddressRegistry.sol";
import "./interfaces/IVault.sol";
import "./interfaces/IVaultFactory.sol";
import "./libraries/helpers/Errors.sol";

contract VaultRegistry is Ownable, IVaultFactory {
    mapping(uint256 => address) public vaults;
    mapping(address => bool) public isRegistered;
    uint256 public nextVaultID;

    // global address provider
    address public immutable addressRegistry;

    constructor(address _addressRegistry) {
        require(_addressRegistry != address(0), Errors.VL_ADDRESS_CANNOT_ZERO);
        addressRegistry = _addressRegistry;
        nextVaultID = 1;
    }

    /// @notice  New a Vault which contains the amm pool's info and the debt positions
    /// Each vault has a debt position that is shared by all the vault positions of this vault
    /// @param _newVault The address of the new vault deployed by dev.
    /// @return vaultId The ID of vault
    function newVault(address _newVault) external onlyOwner returns (uint256 vaultId) {
        require(!isRegistered[_newVault], "Vault already registered");
        vaultId = nextVaultID;
        nextVaultID = nextVaultID + 1;

        IVault(_newVault).onReceiveRegisterCallback(vaultId);

        vaults[vaultId] = _newVault;
        isRegistered[_newVault] = true;
        emit NewVault(_newVault, vaultId);
    }
}
