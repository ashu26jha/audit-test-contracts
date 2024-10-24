// SPDX-License-Identifier: MIT

pragma solidity ^0.4.10;

contract IntegerOverflowAdd {
    mapping(address => uint256) public balanceOf;

    // INSECURE
    function transfer(address _to, uint256 _value) public {
        /* Check if sender has balance */
        // <yes> <report> ARITHMETIC
        require(balanceOf[msg.sender] - _value >= 0);
        // <yes> <report> ARITHMETIC
        balanceOf[msg.sender] -= _value;
        // <yes> <report> ARITHMETIC
        balanceOf[_to] += _value;
    }
}
