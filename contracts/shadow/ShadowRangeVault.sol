// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ILendingPool} from "../interfaces/ILendingPool.sol";
import {IShadowV3Pool} from "../interfaces/IShadowV3Pool.sol";
import {IShadowGaugeV3} from "../interfaces/IShadowGaugeV3.sol";
import {IPriceOracle} from "../interfaces/IPriceOracle.sol";
import {IShadowNonfungiblePositionManager} from "../interfaces/IShadowNonfungiblePositionManager.sol";
import {IPositionValueCalculator} from "../interfaces/IPositionValueCalculator.sol";
import {IAddressRegistry} from "../interfaces/IAddressRegistry.sol";
import {AddressId} from "../libraries/helpers/AddressId.sol";
import {IndividualPosition} from "../IndividualPosition.sol";
import {PaymentsUpgradeable} from "../PaymentsUpgradeable.sol";
import {IShadowSwapRouter} from "../interfaces/IShadowSwapRouter.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IShadowRangePositionImpl} from "../interfaces/IShadowRangePositionImpl.sol";

/**
 * @title ShadowRangeVault
 * @dev Indiviual Position Factory that supports create shadow v3 range position.
 * @notice User interacts this contract when open, close, reduce, repay leveraged position. Liquidator also use this contract.
 * @author Mightify team
 */
contract ShadowRangeVault is
    Initializable,
    ReentrancyGuardUpgradeable,
    Ownable2StepUpgradeable,
    PaymentsUpgradeable,
    IVault
{
    uint256 public vaultId; // immutable when initialized
    uint256 public nextPositionID;
    address public addressProvider;
    address public vaultRegistry;
    address public positionImplementation;

    // token config
    address public token0; // immutable when initialized
    address public token1; // immutable when initialized
    uint8 public token0Decimals; // immutable when initialized
    uint8 public token1Decimals; // immutable when initialized

    // lending pool config
    uint256 public token0ReserveId;
    uint256 public token1ReserveId;

    mapping(address => uint256) public positionAddressToId;
    mapping(uint256 => PositionInfo) public positionInfos;
    mapping(address => uint256[]) public positionIds;

    uint256 public liquidationDebtRatio;
    uint256 public liquidationFee;
    uint256 public liquidationCallerFee;
    uint256 public performanceFee;

    // general config
    uint256 public minPositionSize; // in value 100e8

    mapping(address => bool) public liquidators;
    bool public openLiquidationEnabled;

    // shadowV3Pool config
    address public shadowV3Pool;
    address public shadowGauge;

    modifier checkDeadline(uint256 deadline) {
        require(block.timestamp < deadline, "D");
        _;
    }

    function onReceiveRegisterCallback(uint256 _vaultId) external {
        require(msg.sender == vaultRegistry, "IS");
        require(vaultId == 0, "VAR");
        vaultId = _vaultId;
    }

    function initialize(
        address _addressProvider,
        address _vaultRegistry,
        address _shadowV3PoolAddress,
        address _initialPositionImplementation
    ) public initializer {
        _initializePayments(IAddressRegistry(_addressProvider).getAddress(AddressId.ADDRESS_ID_WETH9));
        __ReentrancyGuard_init();
        __Ownable2Step_init();
        token0 = IShadowV3Pool(_shadowV3PoolAddress).token0();
        token1 = IShadowV3Pool(_shadowV3PoolAddress).token1();
        token0Decimals = IERC20Metadata(token0).decimals();
        token1Decimals = IERC20Metadata(token1).decimals();

        addressProvider = _addressProvider;
        vaultRegistry = _vaultRegistry;
        nextPositionID = 1;
        shadowV3Pool = _shadowV3PoolAddress;

        liquidationDebtRatio = 8600;
        liquidationFee = 500;
        performanceFee = 3000;
        minPositionSize = 100e8;

        positionImplementation = _initialPositionImplementation;
    }

    function setLiquidator(address _liquidator, bool _isLiquidator) external onlyOwner {
        liquidators[_liquidator] = _isLiquidator;
    }

    function setLiquidationFeeParams(uint256 _liquidationFee, uint256 _liquidationCallerFeeRatio) external onlyOwner {
        liquidationFee = _liquidationFee;
        liquidationCallerFee = _liquidationCallerFeeRatio;
    }

    function setOpenLiquidationEnabled(bool _openLiquidationEnabled) external onlyOwner {
        openLiquidationEnabled = _openLiquidationEnabled;
    }

    function setPositionImplementation(address _positionImplementation) external onlyOwner {
        positionImplementation = _positionImplementation;
    }

    function setLiquidationDebtRatio(uint256 _liquidationDebtRatio) external onlyOwner {
        liquidationDebtRatio = _liquidationDebtRatio;
    }

    function setReserveIds(uint256 _token0ReserveId, uint256 _token1ReserveId) external onlyOwner {
        address lendingPool = getLendingPool();

        IERC20(token0).approve(lendingPool, type(uint256).max);
        IERC20(token1).approve(lendingPool, type(uint256).max);
        token0ReserveId = _token0ReserveId;
        token1ReserveId = _token1ReserveId;
    }

    function setMinPositionSize(uint256 _minPositionSize) external onlyOwner {
        minPositionSize = _minPositionSize;
    }

    function setPerformanceFee(uint256 _performanceFee) external onlyOwner {
        performanceFee = _performanceFee;
    }

    function setShadowGauge(address _shadowGauge) external onlyOwner {
        shadowGauge = _shadowGauge;
    }

    function openPosition(OpenPositionParams calldata params)
        external
        payable
        nonReentrant
        checkDeadline(params.deadline)
    {
        (uint256 _positionId, address _positionAddress) = _createNewPosition();

        PositionInfo storage positionInfo = positionInfos[_positionId];
        positionInfo.owner = msg.sender;
        positionInfo.vaultId = vaultId;
        positionInfo.positionAddress = _positionAddress;
        positionInfo.positionId = _positionId;
        positionIds[msg.sender].push(_positionId);
        positionAddressToId[_positionAddress] = _positionId;

        // 1. Transferfrom initial user capital from user wallet
        if (params.amount0Principal > 0) {
            pay(token0, msg.sender, address(this), params.amount0Principal);
        }
        if (params.amount1Principal > 0) {
            pay(token1, msg.sender, address(this), params.amount1Principal);
        }

        // 2. Borrow from lending pool
        address lendingPool = getLendingPool();
        if (params.amount0Borrow > 0) {
            positionInfo.token0DebtId = ILendingPool(lendingPool).newDebtPosition(token0ReserveId);

            ILendingPool(lendingPool).borrow(address(this), positionInfo.token0DebtId, params.amount0Borrow);
        }
        if (params.amount1Borrow > 0) {
            positionInfo.token1DebtId = ILendingPool(lendingPool).newDebtPosition(token1ReserveId);

            ILendingPool(lendingPool).borrow(address(this), positionInfo.token1DebtId, params.amount1Borrow);
        }

        require(
            getDebtRatioFromAmounts(
                params.amount0Principal, params.amount1Principal, params.amount0Borrow, params.amount1Borrow
            ) < liquidationDebtRatio,
            "Borrow value is too high"
        );

        if (params.amount0Principal > 0 || params.amount0Borrow > 0) {
            pay(token0, address(this), positionInfo.positionAddress, params.amount0Principal + params.amount0Borrow);
        }
        if (params.amount1Principal > 0 || params.amount1Borrow > 0) {
            pay(token1, address(this), positionInfo.positionAddress, params.amount1Principal + params.amount1Borrow);
        }
        // 3. open position
        (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1) = IShadowRangePositionImpl(
            positionInfo.positionAddress
        ).openPosition(
            IShadowRangePositionImpl.OpenPositionParams({
                amount0Desired: params.amount0Desired,
                amount1Desired: params.amount1Desired,
                tickLower: params.tickLower,
                tickUpper: params.tickUpper,
                positionOwner: msg.sender
            })
        );

        require(getPositionValueByNftId(tokenId) > minPositionSize, "PVL");

        positionInfo.shadowPositionId = tokenId;
        positionInfo.tickLower = params.tickLower;
        positionInfo.tickUpper = params.tickUpper;
        positionInfo.ul = params.ul;
        positionInfo.ll = params.ll;

        emit PositionOpened(
            msg.sender,
            vaultId,
            _positionId,
            _positionAddress,
            params.amount0Principal,
            params.amount1Principal,
            amount0,
            amount1,
            liquidity,
            block.timestamp
        );

        if (msg.value > 0) {
            refundETH();
        }
        require(getDebtRatio(_positionId) < liquidationDebtRatio, "DRH");
    }

    function closePosition(uint256 positionId)
        external
        nonReentrant
        returns (uint256 token0Balance, uint256 token1Balance)
    {
        PositionInfo memory positionInfo = positionInfos[positionId];
        require(positionInfo.owner == msg.sender, "NO");
        require(getDebtRatio(positionId) < liquidationDebtRatio, "DRH");
        (token0Balance, token1Balance) = _closePosition(positionId);
    }

    function fullfillLimitOrder(uint256 positionId) external nonReentrant {
        PositionInfo memory positionInfo = positionInfos[positionId];
        int24 currentTick = IPositionValueCalculator(
            IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_SHADOW_POSITION_VALUE_CALCULATOR)
        ).getCurrentTick(shadowV3Pool);

        if (
            (positionInfo.ll != 0 && currentTick < positionInfo.ll)
                || (positionInfo.ul != 0 && currentTick > positionInfo.ul)
        ) {
            _closePosition(positionId);
        } else {
            revert("Current tick is not in the position range");
        }

        require(getDebtRatio(positionId) < liquidationDebtRatio, "DRH");
    }

    function _closePosition(uint256 positionId) internal returns (uint256, uint256) {
        PositionInfo memory positionInfo = positionInfos[positionId];

        (uint128 liquidity, uint256 token0Reduced, uint256 token1Reduced, uint256 token0Balance, uint256 token1Balance)
        = IShadowRangePositionImpl(positionInfo.positionAddress).closePosition();

        (uint256 currentDebt0, uint256 currentDebt1) = getPositionDebt(positionId);
        require(currentDebt0 == 0 && currentDebt1 == 0, "Still debt");

        emit PositionClosed(
            positionInfo.owner,
            vaultId,
            positionId,
            positionInfo.positionAddress,
            token0Reduced,
            token1Reduced,
            liquidity,
            block.timestamp
        );

        return (token0Balance, token1Balance);
    }

    function reducePosition(ReducePositionParams calldata params) external nonReentrant {
        PositionInfo memory positionInfo = positionInfos[params.positionId];
        require(positionInfo.owner == msg.sender, "Not the owner");
        require(params.reducePercentage > 0 && params.reducePercentage < 10000, "Invalid reduce percentage");
        require(getDebtRatio(params.positionId) < liquidationDebtRatio, "Debt ratio is too high");

        (uint128 reduceLiquidity,,) = IShadowRangePositionImpl(positionInfo.positionAddress).reducePosition(
            params.reducePercentage, params.amount0ToSwap, params.amount1ToSwap
        );

        require(getPositionValueByNftId(positionInfo.shadowPositionId) > minPositionSize, "PVL");

        emit PositionReduced(positionInfo.owner, vaultId, params.positionId, reduceLiquidity, block.timestamp);
    }

    function repayExact(uint256 positionId, uint256 amount0, uint256 amount1) external payable {
        PositionInfo storage positionInfo = positionInfos[positionId];

        // 1. Transferfrom initial user capital from user wallet
        address lendingPool = getLendingPool();
        if (amount0 > 0 && positionInfo.token0DebtId != 0) {
            (uint256 currentDebt0,) = ILendingPool(lendingPool).getCurrentDebt(positionInfo.token0DebtId);
            if (amount0 > currentDebt0) {
                amount0 = currentDebt0;
            }

            pay(token0, msg.sender, address(this), amount0);

            ILendingPool(lendingPool).repay(address(this), positionInfo.token0DebtId, amount0);
        }
        if (amount1 > 0 && positionInfo.token1DebtId != 0) {
            (uint256 currentDebt1,) = ILendingPool(lendingPool).getCurrentDebt(positionInfo.token1DebtId);
            if (amount1 > currentDebt1) {
                amount1 = currentDebt1;
            }

            pay(token1, msg.sender, address(this), amount1);

            ILendingPool(lendingPool).repay(address(this), positionInfo.token1DebtId, amount1);
        }

        if (msg.value > 0) {
            refundETH();
        }
    }

    function liquidatePosition(uint256 positionId) external nonReentrant {
        PositionInfo memory positionInfo = positionInfos[positionId];
        require(positionInfo.owner != address(0), "Position does not exist");
        require(getDebtRatio(positionId) > liquidationDebtRatio, "Debt ratio is too low");

        if (!openLiquidationEnabled) {
            require(liquidators[msg.sender], "Not a liquidator");
        }

        (
            ,
            uint256 token0Reduced,
            uint256 token1Reduced,
            uint256 token0Fees,
            uint256 token1Fees,
            uint256 token0Left,
            uint256 token1Left
        ) = IShadowRangePositionImpl(positionInfo.positionAddress).liquidatePosition(msg.sender);

        emit PositionLiquidated(
            positionInfo.owner,
            vaultId,
            positionId,
            token0Reduced,
            token1Reduced,
            token0Fees,
            token1Fees,
            token0Left,
            token1Left,
            block.timestamp
        );
        (uint256 currentDebt0, uint256 currentDebt1) = getPositionDebt(positionId);
        require(currentDebt0 == 0 && currentDebt1 == 0, "Still debt");
    }

    function claimRewards(uint256 positionId) external nonReentrant {
        IShadowRangePositionImpl(positionInfos[positionId].positionAddress).claimRewards();

        require(getDebtRatio(positionId) < liquidationDebtRatio, "Debt ratio is too high");
    }

    function claimCallback(address reward, uint256 amount) external {
        uint256 positionId = positionAddressToId[msg.sender];
        require(positionId != 0, "Not a position");
        uint256 feeAmount = amount * performanceFee / 10000;
        pay(reward, msg.sender, positionInfos[positionId].owner, amount - feeAmount);
        pay(reward, msg.sender, performanceFeeRecipient(), feeAmount);

        emit RewardClaimed(positionInfos[positionId].owner, vaultId, positionId, reward, amount - feeAmount, feeAmount);
    }

    function _createNewPosition() internal returns (uint256 newPositionId, address positionAddress) {
        positionAddress = address(new IndividualPosition(nextPositionID));
        newPositionId = nextPositionID;

        nextPositionID = nextPositionID + 1;
    }

    function getTokenPrice(address token) public view returns (uint256) {
        return IPriceOracle(IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_PRICE_ORACLE))
            .getTokenPrice(token);
    }

    function getPositionAmounts(uint256 positionId) public view returns (uint256 amount0, uint256 amount1) {
        return getPositionAmountsByNftId(positionInfos[positionId].shadowPositionId);
    }

    function getPositionAmountsByNftId(uint256 nftId) public view returns (uint256 amount0, uint256 amount1) {
        return IPositionValueCalculator(
            IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_SHADOW_POSITION_VALUE_CALCULATOR)
        ).principal(
            IShadowNonfungiblePositionManager(
                IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_SHADOW_NONFUNGIBLE_POSITION_MANAGER)
            ),
            nftId,
            shadowV3Pool
        );
    }

    function getPositionValue(uint256 positionId) public view returns (uint256 value) {
        (uint256 amount0, uint256 amount1) = getPositionAmounts(positionId);
        return amount0 * getTokenPrice(token0) / 10 ** token0Decimals
            + amount1 * getTokenPrice(token1) / 10 ** token1Decimals;
    }

    function getPositionValueByNftId(uint256 nftId) public view returns (uint256 value) {
        (uint256 amount0, uint256 amount1) = getPositionAmountsByNftId(nftId);
        return amount0 * getTokenPrice(token0) / 10 ** token0Decimals
            + amount1 * getTokenPrice(token1) / 10 ** token1Decimals;
    }

    function getDebtValue(uint256 positionId) public view returns (uint256 value) {
        (uint256 amount0Debt, uint256 amount1Debt) = getPositionDebt(positionId);
        return amount0Debt * getTokenPrice(token0) / 10 ** token0Decimals
            + amount1Debt * getTokenPrice(token1) / 10 ** token1Decimals;
    }

    function getPositionDebt(uint256 positionId) public view returns (uint256 amount0Debt, uint256 amount1Debt) {
        address lendingPool = getLendingPool();
        if (positionInfos[positionId].token0DebtId != 0) {
            (amount0Debt,) = ILendingPool(lendingPool).getCurrentDebt(positionInfos[positionId].token0DebtId);
        }
        if (positionInfos[positionId].token1DebtId != 0) {
            (amount1Debt,) = ILendingPool(lendingPool).getCurrentDebt(positionInfos[positionId].token1DebtId);
        }
    }

    function getDebtRatioFromAmounts(
        uint256 amount0Principal,
        uint256 amount1Principal,
        uint256 amount0Borrow,
        uint256 amount1Borrow
    ) public view returns (uint256 debtRatio) {
        uint256 principalValue = amount0Principal * getTokenPrice(token0) / 10 ** token0Decimals
            + amount1Principal * getTokenPrice(token1) / 10 ** token1Decimals;
        uint256 borrowValue = amount0Borrow * getTokenPrice(token0) / 10 ** token0Decimals
            + amount1Borrow * getTokenPrice(token1) / 10 ** token1Decimals;
        return borrowValue * 10000 / (principalValue + borrowValue);
    }

    function getDebtRatio(uint256 positionId) public view returns (uint256 debtRatio) {
        return getDebtValue(positionId) * 10000 / getPositionValue(positionId);
    }

    function getLendingPool() public view returns (address) {
        return IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_LENDING_POOL);
    }

    function getPositionIds(address owner) public view returns (uint256[] memory) {
        return positionIds[owner];
    }

    function getPositionInfos(uint256 positionId) public view returns (PositionInfo memory) {
        return positionInfos[positionId];
    }

    function liquidationFeeRecipient() public view returns (address) {
        return IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_LIQUIDATION_FEE_RECIPIENT);
    }

    function performanceFeeRecipient() public view returns (address) {
        return IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_PERFORMANCE_FEE_RECIPIENT);
    }

    function getCurrentTick() public view returns (int24) {
        return IPositionValueCalculator(
            IAddressRegistry(addressProvider).getAddress(AddressId.ADDRESS_ID_SHADOW_POSITION_VALUE_CALCULATOR)
        ).getCurrentTick(shadowV3Pool);
    }
}
