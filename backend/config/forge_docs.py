FORGE_STD_ASSERTIONS = """
The Forge Standard Library provides various assertion functions that help validate the behavior of smart contracts during testing. Here are the key assertions with examples:

1. `assertTrue(condition)` - Verifies that a condition is true.
   Example: `assertTrue(balance > 0, "Balance must be positive");`

2. `assertFalse(condition)` - Ensures the condition is false.
   Example: `assertFalse(isActive, "The contract should be inactive");`

3. `assertEq(a, b)` - Confirms that `a` is equal to `b` (works for various types like addresses, ints, uints, strings).
   Example: `assertEq(balance, 100);`

4. `assertEqDecimal(a, b, decimals)` - Asserts that `a` equals `b` with a specific decimal precision.
   Example: `assertEqDecimal(balance, expectedBalance, 18);`

5. `assertNotEq(a, b)` - Ensures `a` and `b` are not equal.
   Example: `assertNotEq(owner, address(0));`

6. `assertLt(a, b)` - Confirms that `a` is less than `b`.
   Example: `assertLt(age, 18);`

7. `assertGt(a, b)` - Verifies that `a` is greater than `b`.
   Example: `assertGt(balance, 0);`

8. `assertLe(a, b)` - Ensures `a` is less than or equal to `b`.
   Example: `assertLe(balance, maxBalance);`

9. `assertGe(a, b)` - Asserts that `a` is greater than or equal to `b`.
   Example: `assertGe(balance, minBalance);`

10. `assertApproxEqAbs(a, b, tolerance)` - Confirms that `a` is approximately equal to `b` within an absolute tolerance.
    Example: `assertApproxEqAbs(value, expectedValue, 10);`

11. `assertApproxEqRel(a, b, tolerance)` - Verifies that `a` and `b` are approximately equal within a relative tolerance.
    Example: `assertApproxEqRel(value, expectedValue, 0.01);`

12. `fail()` - Forces the test to fail, useful for unreachable code.
    Example: `fail("Test should never reach this point.");`
"""

FORGE_STD_CHEATS = """
The Forge Standard Library provides powerful cheat codes and utilities for testing smart contracts effectively. Here are the main features and examples:

1. `std-logs` - Use `log_*` methods to output values during tests. Supports logging `uint`, `address`, `string`, and more. It helps in verifying the internal state at any point.
   Example: `emit log_uint(amount);`

2. `skip(seconds)` - Skips forward in time by a given number of seconds. Useful for testing time-sensitive functions like staking or vesting.
   Example: `skip(3600); // Skip 1 hour`

3. `rewind(seconds)` - Moves backward in time, similar to `skip`, but in reverse. This is used for scenarios where you need to test how contracts behave if time is moved back.
   Example: `rewind(300); // Rewind 5 minutes`

4. `hoax(address)` - Impersonates another address for contract calls. Used to simulate interactions from different accounts in tests.
   Example: `hoax(userAddress);`

5. `startHoax(address)` - Like `hoax()`, but it persists across multiple transactions, until `stopHoax()` is called.
   Example: `startHoax(userAddress);`

6. `deal(address, amount)` - Sets the balance of a given address to the specified amount.
   Example: `deal(userAddress, 100 ether);`

7. `deployCode()` - Deploys a contract using the bytecode from a file. Useful for dynamically deploying contracts during tests.
   Example: `address newContract = deployCode("MyContract.sol");`

8. `deployCodeTo(address)` - Deploys a contract at a specific address. This is useful when you need a contract deployed at a deterministic address.
   Example: `deployCodeTo(newAddress, "MyContract.sol");`

9. `bound(value, min, max)` - Constrains a given value between a min and max range. Ideal for fuzzing or testing boundary conditions.
   Example: `value = bound(value, 1, 100);`

10. `changePrank(address)` - Changes the sender address mid-test without needing to restart the transaction.
   Example: `changePrank(newSender);`

11. `makeAddr(name)` - Generates a new address by hashing a string (useful for quickly creating mock addresses).
   Example: `address newAddr = makeAddr("mockUser");`

12. `makeAddrAndKey(name)` - Generates both an address and private key from a string, for when you need both in tests.
   Example: `(address addr, uint256 privKey) = makeAddrAndKey("tester");`

13. `noGasMetering()` - Turns off gas metering in the EVM for the test, allowing you to bypass gas limits during testing.
   Example: `noGasMetering();`

These cheat codes allow you to simulate different scenarios, control execution flow, and manipulate state during smart contract testing, ensuring more efficient and comprehensive tests.
"""

FORGE_STD_ERRORS = """
The Forge Standard Library provides several common error types for more granular testing of smart contracts. Below are key errors and how they can be implemented:

1. **assertionError**: This error occurs when an assertion fails. It’s useful for ensuring that specific conditions hold true in your tests.
   Example: `assert(true == false, "assertionError occurred");`

2. **arithmeticError**: Typically thrown when an arithmetic operation fails (e.g., division by zero or overflow). Ensures your contract handles arithmetic safely.
   Example: `assert(false, "arithmeticError occurred");`

3. **divisionError**: Raised when a division by zero occurs. Use this error to catch and handle division issues in your tests.
   Example: `assert(false, "divisionError: Division by zero occurred");`

4. **enumConversionError**: Occurs when trying to convert an invalid value to an enum. This ensures only valid enum values are processed.
   Example: `assert(false, "enumConversionError occurred");`

5. **encodeStorageError**: Thrown when an issue arises in storage encoding. Useful for ensuring correct storage behavior.
   Example: `assert(false, "encodeStorageError occurred");`

6. **popError**: Raised when trying to pop from an empty array. You can use this to test boundary cases involving dynamic arrays.
   Example: `assert(false, "popError: Tried to pop from an empty array");`

7. **indexOOBError**: Index out-of-bounds error, typically thrown when accessing an array with an invalid index.
   Example: `assert(false, "indexOOBError: Array index is out of bounds");`

8. **memOverflowError**: Thrown when memory overflow occurs. This helps to check the memory boundaries in complex contract logic.
   Example: `assert(false, "memOverflowError occurred");`

9. **zeroVarError**: Raised when encountering an invalid zero value in an operation. Useful for ensuring that zero values are handled correctly.
   Example: `assert(false, "zeroVarError: Zero value found where not allowed");`
"""

FORGE_STD_FEATURES = """
The Forge Standard Library provides various utilities that enhance smart contract development and testing. Below are the key functions and their usage:

1. **stdStorage** - Enables easy manipulation of contract storage. It allows you to find and write to specific storage slots without knowing the slot number manually.
   Example: `stdstore.target(contract).sig("value()").checked_write(100);`

2. **abs(value)** - Returns the absolute value of an integer. Useful when comparing values in test cases.
   Example: `uint256 result = abs(intValue);`

3. **delta(a, b)** - Calculates the absolute difference between two values, `a` and `b`. It’s commonly used for tolerance checks in test scenarios.
   Example: `uint256 difference = delta(value1, value2);`

4. **percentDelta(a, b)** - Computes the percentage difference between `a` and `b`. This helps in tests requiring precision checks, such as price changes or balances.
   Example: `uint256 percDiff = percentDelta(125, 100); // 25%`

5. **deriveRememberKey(mnemonic, index)** - Derives and stores a private key from a given mnemonic phrase and index. It’s useful when you need to simulate multiple addresses in testing.
   Example: `(address addr, uint256 privKey) = deriveRememberKey("test mnemonic", 0);`

6. **computeCreateAddress(deployer, nonce)** - Calculates the deterministic address for a contract based on the deployer address and nonce, following the `CREATE2` opcode rules.
   Example: `address contractAddress = computeCreateAddress(deployer, nonce);`
"""
