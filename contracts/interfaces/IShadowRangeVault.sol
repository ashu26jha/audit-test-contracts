// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;

interface IShadowRangeVault {
    function shadowV3Pool() external view returns (address);
    function shadowGauge() external view returns (address);
}
