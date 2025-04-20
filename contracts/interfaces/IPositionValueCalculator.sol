// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IShadowNonfungiblePositionManager.sol";

interface IPositionValueCalculator {
    function principal(IShadowNonfungiblePositionManager positionManager, uint256 tokenId, address pool)
        external
        view
        returns (uint256 amount0, uint256 amount1);

    function getCurrentTick(address v3Pool) external view returns (int24);
}
