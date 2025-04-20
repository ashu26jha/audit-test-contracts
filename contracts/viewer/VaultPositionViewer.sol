// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IVault} from "../interfaces/IVault.sol";
import {IAddressRegistry} from "../interfaces/IAddressRegistry.sol";
import {AddressId} from "../interfaces/IAddressRegistry.sol";

interface IPositionImpl {
    function claimableRewards() external view returns (address[] memory, uint256[] memory);
}

interface INFTPositionManager {
    function positions(uint256 tokenId)
        external
        view
        returns (
            address token0,
            address token1,
            int24 tickSpacing,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        );
}

contract VaultPositionViewer {
    address addressProvider;

    constructor(address _addressProvider) {
        addressProvider = _addressProvider;
    }

    function getPositionIds(address vault, address owner) public view returns (uint256[] memory) {
        return IVault(vault).getPositionIds(owner);
    }

    struct PositionInfo {
        address vault;
        uint256 id;
        address token0;
        address token1;
        uint256 amount0;
        uint256 amount1;
        uint256 amount0Debt;
        uint256 amount1Debt;
        uint256 debtRatio;
        uint256 price0;
        uint256 price1;
        //
        address positionAddress;
        uint256 positionNftId;
        uint128 liquidity;
        int24 tickUpper;
        int24 tickLower;
        int24 currentTick;
        int24 ul;
        int24 ll;
        bool inRange;
        address[] rewards;
        uint256[] rewardsAmounts;
    }

    function getUserPosition(address vault, address owner) public view returns (PositionInfo[] memory) {
        uint256[] memory ids = getPositionIds(vault, owner);
        PositionInfo[] memory positions = new PositionInfo[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            positions[i].vault = vault;
            positions[i].id = ids[i];
            positions[i].token0 = IVault(vault).token0();
            positions[i].token1 = IVault(vault).token1();
            (positions[i].amount0, positions[i].amount1) = IVault(vault).getPositionAmounts(ids[i]);
            if (positions[i].amount0 > 0 || positions[i].amount1 > 0) {
                (positions[i].amount0Debt, positions[i].amount1Debt) = IVault(vault).getPositionDebt(ids[i]);
                positions[i].debtRatio = IVault(vault).getDebtRatio(ids[i]);
            }
            positions[i].price0 = IVault(vault).getTokenPrice(positions[i].token0);
            positions[i].price1 = IVault(vault).getTokenPrice(positions[i].token1);

            IVault.PositionInfo memory positionInfo = IVault(vault).getPositionInfos(ids[i]);

            positions[i].positionAddress = positionInfo.positionAddress;
            positions[i].positionNftId = positionInfo.shadowPositionId;
            positions[i].tickUpper = positionInfo.tickUpper;
            positions[i].tickLower = positionInfo.tickLower;
            positions[i].ul = positionInfo.ul;
            positions[i].ll = positionInfo.ll;

            positions[i].inRange = positions[i].amount0 > 0 && positions[i].amount1 > 0;

            (positions[i].rewards, positions[i].rewardsAmounts) =
                IPositionImpl(positionInfo.positionAddress).claimableRewards();

            positions[i].currentTick = IVault(vault).getCurrentTick();

            (,,,,, positions[i].liquidity,,,,) = INFTPositionManager(
                IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_SHADOW_NONFUNGIBLE_POSITION_MANAGER)
            ).positions(positionInfo.shadowPositionId);
        }
        return positions;
    }

    function getUserPositions(address[] memory vaults, address owner) public view returns (PositionInfo[][] memory) {
        PositionInfo[][] memory positions = new PositionInfo[][](vaults.length);
        for (uint256 i = 0; i < vaults.length; i++) {
            positions[i] = getUserPosition(vaults[i], owner);
        }
        return positions;
    }
}
