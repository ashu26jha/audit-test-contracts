// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {
    function onReceiveRegisterCallback(uint256 vaultId) external;

    event PositionOpened(
        address indexed owner,
        uint256 vaultId,
        uint256 positionId,
        address positionAddress,
        uint256 amount0Principal,
        uint256 amount1Principal,
        uint256 amount0Position,
        uint256 amount1Position,
        uint128 liquidity,
        uint256 timestamp
    );

    event PositionClosed(
        address indexed owner,
        uint256 vaultId,
        uint256 positionId,
        address positionAddress,
        uint256 amount0Position,
        uint256 amount1Position,
        uint128 liquidity,
        uint256 timestamp
    );
    event PositionReduced(
        address indexed owner, uint256 vaultId, uint256 positionId, uint128 reducedLiquidity, uint256 timestamp
    );
    event PositionLiquidated(
        address indexed owner,
        uint256 vaultId,
        uint256 positionId,
        uint256 token0Reduced,
        uint256 token1Reduced,
        uint256 token0Fees,
        uint256 token1Fees,
        uint256 token0Left,
        uint256 token1Left,
        uint256 timestamp
    );

    event RewardClaimed(
        address indexed owner,
        uint256 vaultId,
        uint256 positionId,
        address reward,
        uint256 userAmount,
        uint256 feeAmount
    );

    struct OpenPositionParams {
        // amount from user
        uint256 amount0Principal;
        uint256 amount1Principal;
        // amount from lending pool
        uint256 amount0Borrow;
        uint256 amount1Borrow;
        // amount needed for
        uint256 amount0SwapNeededForPosition; // if this is > 0, amount1SwapNeededForPosition should be 0
        uint256 amount1SwapNeededForPosition; // if this is > 0, amount0Desired should be 0
        // full position composition
        uint256 amount0Desired; //
        uint256 amount1Desired;
        // deadline
        uint256 deadline;
        // position range
        int24 tickLower;
        int24 tickUpper;
        // limit order
        int24 ul;
        int24 ll;
    }

    struct ReducePositionParams {
        uint256 positionId;
        uint128 reducePercentage;
        uint256 amount0ToSwap;
        uint256 amount1ToSwap;
    }

    struct PositionInfo {
        address owner;
        uint256 vaultId;
        uint256 positionId;
        address positionAddress;
        uint256 shadowPositionId;
        uint256 token0DebtId;
        uint256 token1DebtId;
        // position range
        int24 tickUpper;
        int24 tickLower;
        // limit order
        int24 ul;
        int24 ll;
    }

    function openPosition(OpenPositionParams calldata params) external payable;

    function reducePosition(ReducePositionParams calldata params) external;

    function repayExact(uint256 positionId, uint256 amount0, uint256 amount1) external payable;

    function closePosition(uint256 positionId) external returns (uint256 token0Balance, uint256 token1Balance);

    function fullfillLimitOrder(uint256 positionId) external;

    function liquidatePosition(uint256 positionId) external;

    function claimRewards(uint256 positionId) external;

    function claimCallback(address reward, uint256 amount) external;

    function token0() external view returns (address);

    function token1() external view returns (address);

    function token0Decimals() external view returns (uint8);

    function token1Decimals() external view returns (uint8);

    function performanceFee() external view returns (uint256);

    function performanceFeeRecipient() external view returns (address);

    function liquidationFee() external view returns (uint256);

    function liquidationCallerFee() external view returns (uint256);

    function liquidationFeeRecipient() external view returns (address);

    function addressProvider() external view returns (address);

    function getPositionAmounts(uint256 positionId) external view returns (uint256, uint256);
    function getPositionDebt(uint256 positionId) external view returns (uint256, uint256);
    function getTokenPrice(address token) external view returns (uint256);
    function getPositionValue(uint256 positionId) external view returns (uint256);
    function getDebtValue(uint256 positionId) external view returns (uint256);
    function getDebtRatio(uint256 positionId) external view returns (uint256);
    function getPositionIds(address owner) external view returns (uint256[] memory);

    function getPositionInfos(uint256 positionId) external view returns (PositionInfo memory);
    function getCurrentTick() external view returns (int24);
}
