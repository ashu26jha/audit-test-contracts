// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract Caller {
    function callAddress(address a) public {
        // <yes> <report> UNCHECKED_LOW_LEVEL_CALLS
        a.call("");
    }
}
