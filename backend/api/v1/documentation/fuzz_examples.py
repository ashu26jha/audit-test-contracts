# TODO: Improve this documentation a lot

FUZZ_EXAMPLES = """

This is a test

```solidity
//SPDX-License-Identifier: MIT

import {Test} from "forge-std/Test.sol";
import {SimpleDapp} from "../src/SimpleDapp.sol";

pragma solidity ^0.8.23;

/// @title Test for SimpleDapp Contract
/// @notice This contract implements Fuzz testing for SimpleDapp
contract SimpleDappTest is Test {
    SimpleDapp simpleDapp;
    address public user;

    ///@notice Set up the test by deploying SimpleDapp
    function setUp() public {
        simpleDapp = new SimpleDapp();
        user = address(1); // Assign a non-zero address to user
    }

    /// @notice FUzz test for deposit and Withdraw functions
    /// @dev Test the invariant that a user can't withdraw more than they deposit
    /// @param depositAmount The amount of ETH to deposit
    /// @param withdrawAmount The amount of ETH to withdraw
    function testDepositAndWithdraw(
        // We set the depositAmount and withdrawAmount to be input parameters 👇👇👇
        uint256 depositAmount,
        uint256 withdrawAmount
    )
        public
        payable
    // Foundry will generate random values for the input parameters 👆👆👆
    {
        // Ensure the user has enough Ether to cover the deposit
        uint256 initialUserBalance = 100 ether;
        vm.deal(user, initialUserBalance);

        // Only attempt deposit if the user has enough balance
        if (depositAmount <= initialUserBalance) {
            simpleDapp.deposit{value: depositAmount}();

            if (withdrawAmount <= depositAmount) {
                simpleDapp.withdraw(withdrawAmount);
                assertEq(
                    simpleDapp.balances(user),
                    depositAmount - withdrawAmount,
                    "Balance after withdrawal should match expected value"
                );
            } else {
                // Expect a revert due to insufficient balance
                vm.expectRevert("Insufficient balance");
                simpleDapp.withdraw(withdrawAmount);
            }
        }
    }
}
```

For this contract
```solidity
//SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

/// @title SimpleDapp
/// @notice This contract allows for deposits and withdrawals of ETH by users
contract SimpleDapp {
    mapping(address => uint256) public balances;

    /// @notice Deposit ETH into the contract
    /// @dev This function will deposit ETH into the contract and update the mapping balances.abi
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraw ETH from the contract
    /// @dev This function will withdraw ETH from the contract and update the mapping balances.
    /// @param _amount The amount of ETH to withdraw
    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Withdraw failed");
    }
}
```

Example 2:
```solidity
// SPDX-License-Identifier: MIT

import {Test} from "forge-std/Test.sol";
import {AlwaysEven} from "../src/AlwaysEven.sol";

// We need to import the invariant contract from forge-std
import {StdInvariant} from "forge-std/StdInvariant.sol";

pragma solidity ^0.8.12;

contract AlwaysEvenTestStateful is StdInvariant, Test {
    AlwaysEven alwaysEven;

    function setUp() public {
        alwaysEven = new AlwaysEven();
        // we must define the target contract which is going to start executing the functions with random inputs
        targetContract(address(alwaysEven));
    }

    function invariant_testsetEvenNumber() public view {
        assert(alwaysEven.alwaysEvenNumber() % 2 == 0);
    }
}
```

Contract:

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;

contract AlwaysEven {
    uint256 public alwaysEvenNumber;
    uint256 public hiddenValue;

    function setEvenNumber(uint256 inputNumber) public {
        if (inputNumber % 2 == 0) {
            alwaysEvenNumber += inputNumber;
        }

        // This conditional will break the invariant which must be always be even
        // 👇👇👇 in a stateless scenario this will never be tru, because hiddenValue will be Always 0
        if (hiddenValue == 8) {
            alwaysEvenNumber = 3;
        }

        // We set the hiddenValue to the inputNumber at the end of the function
        // In a stateful scenario, this value will be remembered for the next call

        hiddenValue = inputNumber;
    }
}
```
"""
