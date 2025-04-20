// SPDX-License-Identifier: gpl-3.0
pragma solidity ^0.8.0;
pragma abicoder v2;

library AddressId {
    uint256 constant ADDRESS_ID_WETH9 = 1;
    uint256 constant ADDRESS_ID_LENDING_POOL = 9;
    uint256 constant ADDRESS_ID_VAULT_FACTORY = 10;
    uint256 constant ADDRESS_ID_TREASURY = 11; // receive lending fees
    uint256 constant ADDRESS_ID_PERFORMANCE_FEE_RECIPIENT = 12; // receive performance fees
    uint256 constant ADDRESS_ID_LIQUIDATION_FEE_RECIPIENT = 13; // receive liquidation fees

    uint256 constant ADDRESS_ID_PRICE_ORACLE = 100;

    uint256 constant ADDRESS_ID_SHADOW_ROUTER = 300;
    uint256 constant ADDRESS_ID_SHADOW_NONFUNGIBLE_POSITION_MANAGER = 301;
    uint256 constant ADDRESS_ID_SHADOW_POSITION_VALUE_CALCULATOR = 302;
}
