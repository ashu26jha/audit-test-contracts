// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IShadowGaugeV3} from "../interfaces/IShadowGaugeV3.sol";
import {IShadowNonfungiblePositionManager} from "../interfaces/IShadowNonfungiblePositionManager.sol";
import {IShadowV3Pool} from "../interfaces/IShadowV3Pool.sol";
import {PaymentsUpgradeable} from "../PaymentsUpgradeable.sol";
import {IShadowRangePositionImpl} from "../interfaces/IShadowRangePositionImpl.sol";
import {IPayments} from "../interfaces/IPayments.sol";
import {IAddressRegistry} from "../interfaces/IAddressRegistry.sol";
import {AddressId} from "../interfaces/IAddressRegistry.sol";
import {IShadowSwapRouter} from "../interfaces/IShadowSwapRouter.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {IShadowRangeVault} from "../interfaces/IShadowRangeVault.sol";
import {IShadowX33} from "../interfaces/IShadowX33.sol";

/**
 * @title ShadowRangePositionImpl
 * @dev Implementation of position related operations
 * @notice Only vault can call functions, upgradeable from parents vault.
 * @author Mightify team
 */
contract ShadowRangePositionImpl is IShadowRangePositionImpl, PaymentsUpgradeable {
    address public vault;
    uint256 public positionId;
    address public shadowV3Pool;
    int24 public tickSpacing;
    address public token0;
    address public token1;

    address public positionOwner;
    uint256 public shadowPositionId;

    address public xShadow;
    address public x33;
    address public addressProvider;

    function initialize(uint256 _positionId) external {
        require(vault == address(0), "Already initialized");
        xShadow = 0x5050bc082FF4A74Fb6B0B04385dEfdDB114b2424;
        x33 = 0x3333111A391cC08fa51353E9195526A70b333333;
        vault = msg.sender;
        positionId = _positionId;

        token0 = IVault(msg.sender).token0();
        token1 = IVault(msg.sender).token1();

        IERC20(token0).approve(vault, type(uint256).max);
        IERC20(token1).approve(vault, type(uint256).max);

        shadowV3Pool = IShadowRangeVault(vault).shadowV3Pool();
        tickSpacing = IShadowV3Pool(shadowV3Pool).tickSpacing();

        _initializePayments(IPayments(msg.sender).WETH9());

        addressProvider = IVault(msg.sender).addressProvider();
    }

    modifier onlyVault() {
        require(msg.sender == vault, "Only vault can call this function");
        _;
    }

    function version() external pure returns (uint256) {
        return 1;
    }

    function getX33Adapter() public view returns (address) {
        return 0x9710E10A8f6FbA8C391606fee18614885684548d;
    }

    function getShadowNonfungiblePositionManager() public view returns (address) {
        return IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_SHADOW_NONFUNGIBLE_POSITION_MANAGER);
    }

    function getSwapRouter() public view returns (address) {
        return IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_SHADOW_ROUTER);
    }

    function openPosition(OpenPositionParams memory params)
        external
        onlyVault
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        uint256 token0Balance = IERC20(token0).balanceOf(address(this));
        if (params.amount0Desired > token0Balance) {
            _swapTokenExactInput(
                token1,
                token0,
                IERC20(token1).balanceOf(address(this)) - params.amount1Desired,
                params.amount0Desired - token0Balance
            );
        }

        uint256 token1Balance = IERC20(token1).balanceOf(address(this));
        if (params.amount1Desired > token1Balance) {
            _swapTokenExactInput(
                token0,
                token1,
                IERC20(token0).balanceOf(address(this)) - params.amount0Desired,
                params.amount1Desired - token1Balance
            );
        }
        address shadowNonfungiblePositionManager = getShadowNonfungiblePositionManager();

        IERC20(token0).approve(shadowNonfungiblePositionManager, params.amount0Desired);
        IERC20(token1).approve(shadowNonfungiblePositionManager, params.amount1Desired);

        (tokenId, liquidity, amount0, amount1) = IShadowNonfungiblePositionManager(shadowNonfungiblePositionManager)
            .mint(
            IShadowNonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                tickSpacing: tickSpacing,
                tickLower: params.tickLower,
                tickUpper: params.tickUpper,
                amount0Desired: params.amount0Desired,
                amount1Desired: params.amount1Desired,
                amount0Min: 0,
                amount1Min: 0,
                recipient: address(this),
                deadline: block.timestamp
            })
        );

        shadowPositionId = tokenId;
        positionOwner = params.positionOwner;

        unwrapWETH9(0, positionOwner);

        token0Balance = IERC20(token0).balanceOf(address(this));
        token1Balance = IERC20(token1).balanceOf(address(this));

        if (token0Balance > 0) {
            pay(token0, address(this), positionOwner, token0Balance);
        }
        if (token1Balance > 0) {
            pay(token1, address(this), positionOwner, token1Balance);
        }
    }

    function closePosition()
        external
        onlyVault
        returns (
            uint128 liquidity,
            uint256 token0Reduced,
            uint256 token1Reduced,
            uint256 token0Balance,
            uint256 token1Balance
        )
    {
        _claimFees();
        _claimRewards();

        (,,,,, liquidity,,,,) =
            IShadowNonfungiblePositionManager(getShadowNonfungiblePositionManager()).positions(shadowPositionId);

        (token0Reduced, token1Reduced) = _decreasePosition(liquidity);

        (uint256 currentDebt0, uint256 currentDebt1) = IVault(vault).getPositionDebt(positionId);

        if (currentDebt0 > 0) {
            // repay all token0 debt
            if (currentDebt0 > token0Reduced) {
                // need to swap from token 1 to token0 ,
                // this means we assume that token 1 is in excess
                // in this case, user will receive all collateral in token0
                uint256 amount1Excess = token1Reduced - currentDebt1;
                _swapTokenExactInput(token1, token0, amount1Excess, currentDebt0 - token0Reduced);
            }
            IERC20(token0).approve(vault, currentDebt0);
        }

        if (currentDebt1 > 0) {
            // repay all token1 debt
            if (currentDebt1 > token1Reduced) {
                // need to swap from token 0 to token1,
                // this means we assume that token 0 is in excess
                // in this case, user will receive all collateral in token1
                uint256 amount0Excess = token0Reduced - currentDebt0;
                _swapTokenExactInput(token0, token1, amount0Excess, currentDebt1 - token1Reduced);
            }
            IERC20(token1).approve(vault, currentDebt1);
        }

        IVault(vault).repayExact(positionId, currentDebt0, currentDebt1);

        token0Balance = IERC20(token0).balanceOf(address(this));
        token1Balance = IERC20(token1).balanceOf(address(this));
        if (token0Balance > 0) {
            pay(token0, address(this), positionOwner, token0Balance);
        }
        if (token1Balance > 0) {
            pay(token1, address(this), positionOwner, token1Balance);
        }
    }

    function reducePosition(uint128 reducePercentage, uint256 amount0ToSwap, uint256 amount1ToSwap)
        external
        onlyVault
        returns (uint128 reduceLiquidity, uint256 token0Reduced, uint256 token1Reduced)
    {
        _claimFees();

        (,,,,, uint128 liquidity,,,,) =
            IShadowNonfungiblePositionManager(getShadowNonfungiblePositionManager()).positions(shadowPositionId);

        reduceLiquidity = liquidity * reducePercentage / 10000;

        (token0Reduced, token1Reduced) = _decreasePosition(reduceLiquidity);

        if (amount0ToSwap > 0) {
            _swapTokenExactInput(token0, token1, amount0ToSwap, 0);
        }

        if (amount1ToSwap > 0) {
            _swapTokenExactInput(token1, token0, amount1ToSwap, 0);
        }

        uint256 token0Left = IERC20(token0).balanceOf(address(this));
        uint256 token1Left = IERC20(token1).balanceOf(address(this));

        if (token0Left > 0) {
            IERC20(token0).approve(vault, token0Left);
        }

        if (token1Left > 0) {
            IERC20(token1).approve(vault, token1Left);
        }

        IVault(vault).repayExact(positionId, token0Left, token1Left);

        token0Left = IERC20(token0).balanceOf(address(this));
        token1Left = IERC20(token1).balanceOf(address(this));
        if (token0Left > 0) {
            pay(token0, address(this), positionOwner, token0Left);
        }
        if (token1Left > 0) {
            pay(token1, address(this), positionOwner, token1Left);
        }
    }

    // @temp avoid stack too deep
    struct LiquidationFeeVars {
        uint256 liquidationFee;
        uint256 liquidationCallerFee;
        address liquidationFeeRecipient;
    }

    function liquidatePosition(address caller)
        external
        onlyVault
        returns (
            uint128 liquidity,
            uint256 token0Reduced,
            uint256 token1Reduced,
            uint256 token0Fees,
            uint256 token1Fees,
            uint256 token0Left,
            uint256 token1Left
        )
    {
        _claimFees();
        _claimRewards();
        (,,,,, liquidity,,,,) =
            IShadowNonfungiblePositionManager(getShadowNonfungiblePositionManager()).positions(shadowPositionId);

        (token0Reduced, token1Reduced) = _decreasePosition(liquidity);
        (uint256 currentDebt0, uint256 currentDebt1) = IVault(vault).getPositionDebt(positionId);

        LiquidationFeeVars memory vars = LiquidationFeeVars({
            liquidationFee: IVault(vault).liquidationFee(),
            liquidationCallerFee: IVault(vault).liquidationCallerFee(),
            liquidationFeeRecipient: IVault(vault).liquidationFeeRecipient()
        });
        // handle liquidation fees
        if (token0Reduced > 0) {
            token0Fees = token0Reduced * vars.liquidationFee / 10000;
            pay(token0, address(this), vars.liquidationFeeRecipient, token0Fees);

            uint256 token0CallerFees = token0Fees * vars.liquidationCallerFee / 10000;
            if (token0CallerFees > 0) {
                pay(token0, address(this), caller, token0CallerFees);
            }

            token0Reduced = token0Reduced - token0Fees - token0CallerFees;
        }

        if (token1Reduced > 0) {
            token1Fees = token1Reduced * vars.liquidationFee / 10000;

            pay(token1, address(this), vars.liquidationFeeRecipient, token1Fees);

            uint256 token1CallerFees = token1Fees * vars.liquidationCallerFee / 10000;
            if (token1CallerFees > 0) {
                pay(token1, address(this), caller, token1CallerFees);
            }

            token1Reduced = token1Reduced - token1Fees - token1CallerFees;
        }

        if (currentDebt0 > 0) {
            // repay all token0 debt
            if (currentDebt0 > token0Reduced) {
                uint256 amount1Excess = token1Reduced - currentDebt1;
                _swapTokenExactInput(token1, token0, amount1Excess, currentDebt0 - token0Reduced);
            }
            IERC20(token0).approve(vault, currentDebt0);
        }

        if (currentDebt1 > 0) {
            // repay all token1 debt
            if (currentDebt1 > token1Reduced) {
                uint256 amount0Excess = token0Reduced - currentDebt0;
                _swapTokenExactInput(token0, token1, amount0Excess, currentDebt1 - token1Reduced);
            }
            IERC20(token1).approve(vault, currentDebt1);
        }

        IVault(vault).repayExact(positionId, currentDebt0, currentDebt1);

        token0Left = IERC20(token0).balanceOf(address(this));
        token1Left = IERC20(token1).balanceOf(address(this));
        if (token0Left > 0) {
            pay(token0, address(this), positionOwner, token0Left);
        }
        if (token1Left > 0) {
            pay(token1, address(this), positionOwner, token1Left);
        }
    }

    function claimableRewards() external view returns (address[] memory, uint256[] memory) {
        address shadowGauge = IShadowRangeVault(vault).shadowGauge();
        if (shadowGauge != address(0)) {
            address[] memory tokens = IShadowGaugeV3(shadowGauge).getRewardTokens();
            uint256[] memory amounts = new uint256[](tokens.length);
            for (uint256 i = 0; i < tokens.length; i++) {
                amounts[i] = IShadowGaugeV3(shadowGauge).earned(tokens[i], shadowPositionId);
            }
            return (tokens, amounts);
        }
        return (new address[](0), new uint256[](0));
    }

    function claimRewards() external onlyVault {
        _claimFees();
        _claimRewards();
    }

    function _claimFees() internal {
        IShadowNonfungiblePositionManager(getShadowNonfungiblePositionManager()).collect(
            IShadowNonfungiblePositionManager.CollectParams({
                tokenId: shadowPositionId,
                recipient: address(this),
                amount0Max: type(uint128).max,
                amount1Max: type(uint128).max
            })
        );

        uint256 token0Fees = IERC20(token0).balanceOf(address(this));
        uint256 token1Fees = IERC20(token1).balanceOf(address(this));
        if (token0Fees > 0) {
            IERC20(token0).approve(vault, token0Fees);
            IVault(vault).claimCallback(token0, token0Fees);
        }
        if (token1Fees > 0) {
            IERC20(token1).approve(vault, token1Fees);
            IVault(vault).claimCallback(token1, token1Fees);
        }
    }

    function _claimRewards() internal {
        address shadowGauge = IShadowRangeVault(vault).shadowGauge();
        if (shadowGauge != address(0)) {
            address[] memory tokens = IShadowGaugeV3(shadowGauge).getRewardTokens();
            IShadowGaugeV3(shadowGauge).getReward(shadowPositionId, tokens);

            for (uint256 i = 0; i < tokens.length; i++) {
                uint256 balance = IERC20(tokens[i]).balanceOf(address(this));
                if (balance > 0) {
                    if (tokens[i] == xShadow) {
                        // xShadow is non-transferable token so need to wrap to x33 (liquid xShadow)
                        // and then transfer to beneficiary(user)
                        // but according to shadow's epoch system, wrapping function is locked for specific period
                        // ex) from 12 hours - epoch flips - after 12 hours
                        // so we need to check availability of wrapping function.
                        if (IShadowX33(x33).isUnlocked()) {
                            address x33Adapter = getX33Adapter();
                            IERC20(tokens[i]).approve(x33Adapter, balance);
                            IERC4626(x33Adapter).deposit(balance, address(this));
                            balance = IERC20(x33).balanceOf(address(this));
                            IERC20(x33).approve(vault, balance);
                            IVault(vault).claimCallback(x33, balance);
                        }
                    } else {
                        IERC20(tokens[i]).approve(vault, balance);
                        IVault(vault).claimCallback(tokens[i], balance);
                    }
                }
            }
        }
    }

    function _decreasePosition(uint128 liquidity) internal returns (uint256 amount0, uint256 amount1) {
        IShadowNonfungiblePositionManager(getShadowNonfungiblePositionManager()).decreaseLiquidity(
            IShadowNonfungiblePositionManager.DecreaseLiquidityParams({
                tokenId: shadowPositionId,
                liquidity: liquidity,
                amount0Min: 0,
                amount1Min: 0,
                deadline: block.timestamp
            })
        );

        IShadowNonfungiblePositionManager(getShadowNonfungiblePositionManager()).collect(
            IShadowNonfungiblePositionManager.CollectParams({
                tokenId: shadowPositionId,
                recipient: address(this),
                amount0Max: type(uint128).max,
                amount1Max: type(uint128).max
            })
        );

        amount0 = IERC20(token0).balanceOf(address(this));
        amount1 = IERC20(token1).balanceOf(address(this));
    }

    function _swapTokenExactInput(address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOutMinimum)
        internal
        returns (uint256 amountOut)
    {
        address router =
            IAddressRegistry(IVault(vault).addressProvider()).getAddress(AddressId.ADDRESS_ID_SHADOW_ROUTER);
        IERC20(tokenIn).approve(router, amountIn);

        amountOut = IShadowSwapRouter(router).exactInputSingle(
            IShadowSwapRouter.ExactInputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                tickSpacing: tickSpacing,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: amountOutMinimum,
                sqrtPriceLimitX96: 0
            })
        );
    }

    function _swapTokenExactOutput(address tokenIn, address tokenOut, uint256 amountOut, uint256 amountInMaximum)
        internal
        returns (uint256 amountIn)
    {
        address router =
            IAddressRegistry(IVault(vault).addressProvider()).getAddress(AddressId.ADDRESS_ID_SHADOW_ROUTER);
        IERC20(tokenIn).approve(router, amountInMaximum);

        amountIn = IShadowSwapRouter(router).exactOutputSingle(
            IShadowSwapRouter.ExactOutputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                tickSpacing: tickSpacing,
                recipient: address(this),
                deadline: block.timestamp,
                amountOut: amountOut,
                amountInMaximum: amountInMaximum,
                sqrtPriceLimitX96: 0
            })
        );
    }
}
