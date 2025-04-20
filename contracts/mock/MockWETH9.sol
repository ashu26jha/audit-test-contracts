// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockWETH9
 * @dev Mock implementation of Wrapped Ether (WETH9) for testing purposes
 * Implements basic WETH functionality including deposit (wrap) and withdraw (unwrap)
 */
contract MockWETH9 is ERC20 {
    // Events
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    constructor() ERC20("Wrapped Ether", "WETH") {}

    // Deposit ETH and mint WETH
    function deposit() public payable {
        _mint(msg.sender, msg.value);
        emit Deposit(msg.sender, msg.value);
    }

    // Burn WETH and withdraw ETH
    function withdraw(uint256 wad) public {
        require(balanceOf(msg.sender) >= wad, "WETH: insufficient balance");
        _burn(msg.sender, wad);
        payable(msg.sender).transfer(wad);
        emit Withdrawal(msg.sender, wad);
    }

    // Allow contract to receive ETH
    receive() external payable {
        deposit();
    }

    // Fallback function
    fallback() external payable {
        deposit();
    }
}
