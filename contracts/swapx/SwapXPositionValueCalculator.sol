// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import {ISwapXNonfungiblePositionManager} from "../interfaces/ISwapXNonfungiblePositionManager.sol";
import {LiquidityAmounts} from "../libraries/uniswap-v3/LiquidityAmounts.sol";
import {TickMath} from "../libraries/uniswap-v3/TickMath.sol";
import {ISwapXV3Pool} from "../interfaces/ISwapXV3Pool.sol";

contract SwapXPositionValueCalculator {
    /// @notice Calculates the principal (currently acting as liquidity) owed to the token owner in the event
    /// that the position is burned
    /// @param positionManager The Uniswap V3 NonfungiblePositionManager
    /// @param tokenId The tokenId of the token for which to get the total principal owed
    /// @param pool The address of the Uniswap V3 pool
    /// @return amount0 The principal amount of token0
    /// @return amount1 The principal amount of token1
    function principal(ISwapXNonfungiblePositionManager positionManager, uint256 tokenId, address pool)
        public
        view
        returns (uint256 amount0, uint256 amount1)
    {
        (uint160 sqrtPriceX96,,,,,) = ISwapXV3Pool(pool).globalState();

        (,,,, int24 tickLower, int24 tickUpper, uint128 liquidity,,,,) = positionManager.positions(tokenId);

        return LiquidityAmounts.getAmountsForLiquidity(
            sqrtPriceX96, TickMath.getSqrtRatioAtTick(tickLower), TickMath.getSqrtRatioAtTick(tickUpper), liquidity
        );
    }

    function getCurrentTick(address v3Pool) public view returns (int24) {
        (, int24 tick,,,,) = ISwapXV3Pool(v3Pool).globalState();
        return tick;
    }
}
