// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/AddressRegistry.sol";
import {AddressId} from "../contracts/libraries/helpers/AddressId.sol";

contract AddressRegistryTest is Test {
    AddressRegistry public registry;
    address public constant WETH9_ADDRESS =
        0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address public owner;
    address public user = address(1);

    function setUp() public {
        owner = address(this);
        vm.startPrank(owner);
        registry = new AddressRegistry(WETH9_ADDRESS);
        vm.stopPrank();
    }

    function test_ConstructorSetsWETH9() public view {
        assertEq(
            registry.getAddress(uint256(AddressId.ADDRESS_ID_WETH9)),
            WETH9_ADDRESS
        );
    }

    function test_OwnerCanSetAddress() public {
        uint256 testId = 100;
        address testAddr = address(0x123);

        vm.prank(owner);
        registry.setAddress(testId, testAddr);

        assertEq(registry.getAddress(testId), testAddr);
    }

    function test_GetAddressReturnsCorrectly() public view {
        uint256 testId = uint256(AddressId.ADDRESS_ID_WETH9);
        assertEq(registry.getAddress(testId), WETH9_ADDRESS);
        assertEq(registry.getAddress(0), address(0));
    }

    function test_Fail_NonOwnerCannotSetAddress() public {
        uint256 testId = 101;
        address testAddr = address(0x456);

        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(user);
        registry.setAddress(testId, testAddr);
    }
}
