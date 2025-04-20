// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IShadowRangePositionImpl {
    struct OpenPositionParams {
        uint256 amount0Desired;
        uint256 amount1Desired;
        int24 tickLower;
        int24 tickUpper;
        address positionOwner;
    }

    function openPosition(OpenPositionParams memory params)
        external
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);

    function closePosition()
        external
        returns (
            uint128 liquidity,
            uint256 token0Reduced,
            uint256 token1Reduced,
            uint256 token0Balance,
            uint256 token1Balance
        );

    function reducePosition(uint128 reducePercentage, uint256 amount0ToSwap, uint256 amount1ToSwap)
        external
        returns (uint128 reduceLiquidity, uint256 token0Reduced, uint256 token1Reduced);

    function liquidatePosition(address caller)
        external
        returns (
            uint128 liquidity,
            uint256 token0Reduced,
            uint256 token1Reduced,
            uint256 token0Fees,
            uint256 token1Fees,
            uint256 token0Left,
            uint256 token1Left
        );

    function claimRewards() external;
}
