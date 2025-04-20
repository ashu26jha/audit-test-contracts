// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ILendingPool} from "contracts/interfaces/ILendingPool.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockTestBorrowableVault {
    // prerequisities:
    // register vault
    // borrowingWhitelist
    // borrowing credit
    address lendingPool;

    constructor(address _lendingPool) {
        lendingPool = _lendingPool;
    }

    function onReceiveRegisterCallback(uint256 vaultId) external {}

    function borrow(uint256 amount, uint256 reserveId) external returns (uint256 debtId) {
        debtId = ILendingPool(lendingPool).newDebtPosition(reserveId);
        ILendingPool(lendingPool).borrow(address(this), debtId, amount);
    }

    function repay(uint256 debtId, address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        IERC20(token).approve(lendingPool, amount);
        ILendingPool(lendingPool).repay(address(this), debtId, amount);
    }
}
