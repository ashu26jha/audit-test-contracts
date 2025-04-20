// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {IPriceOracle} from "./interfaces/IPriceOracle.sol";
import "@pythnetwork/pyth-sdk-solidity/IPyth.sol";
import "@pythnetwork/pyth-sdk-solidity/PythStructs.sol";

contract PrimaryPriceOracle is IPriceOracle, Initializable {
    IPyth public pyth;

    address public oracleManager;
    uint256 public maxPriceAge;

    mapping(address => bytes32) public pythPriceIds;

    function initialize(
        address _pyth,
        address _oracleManager,
        address[] memory initialTokens,
        bytes32[] memory priceIds
    ) external initializer {
        pyth = IPyth(_pyth);
        oracleManager = _oracleManager;
        require(
            initialTokens.length == priceIds.length,
            "Initial tokens and price ids length mismatch"
        );
        for (uint256 i = 0; i < initialTokens.length; i++) {
            pythPriceIds[initialTokens[i]] = priceIds[i];
        }

        maxPriceAge = 1 hours;
    }

    modifier onlyOracleManager() {
        require(
            msg.sender == oracleManager,
            "Only oracle manager can call this function"
        );
        _;
    }

    function setOracleManager(
        address _oracleManager
    ) external onlyOracleManager {
        require(
            _oracleManager != address(0),
            "Oracle manager cannot be zero address"
        );
        oracleManager = _oracleManager;
    }

    function setPythPriceId(
        address token,
        bytes32 priceId
    ) external onlyOracleManager {
        pythPriceIds[token] = priceId;
    }

    function setMaxPriceAge(uint256 _maxPriceAge) external onlyOracleManager {
        maxPriceAge = _maxPriceAge;
    }

    function getTokenPrice(address token) public view returns (uint256) {
        return getPythPrice(token);
    }

    // @audit: Confidence interval of Pyth oracle is not respected
    function getPythPrice(address token) public view returns (uint256) {
        bytes32 priceId = pythPriceIds[token];
        if (priceId == bytes32(0)) {
            revert("PriceId not set");
        }
        PythStructs.Price memory priceStruct = pyth.getPriceUnsafe(priceId);

        require(
            priceStruct.publishTime + maxPriceAge > block.timestamp,
            "Price is too old"
        );

        uint256 price = uint256(uint64(priceStruct.price));

        return price;
    }
}
