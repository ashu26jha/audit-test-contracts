// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Pausable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/// @custom:security-contact hello@fileverse.io
contract HeartMint is
    ERC1155,
    AccessControl,
    ERC1155Pausable,
    ERC1155Supply,
    ERC2771Context
{
    using Counters for Counters.Counter;
    bytes32 public constant URI_SETTER_ROLE = keccak256("URI_SETTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    Counters.Counter private tokenIdCounter;
    // heart mint factor - usually time take to produce a block on that chain
    uint256 public heartMintFactor;
    // max valid block
    uint256 public maxValidBlocks;

    address private immutable trustedForwarder;

    // Mapping owner address to token count
    mapping(bytes32 => uint256) public urlTokenMap;
    mapping(uint256 => bytes32) public reverseUrlTokenMap;

    constructor(
        address defaultAdmin,
        address pauser,
        address minter,
        address _trustedForwarder,
        uint256 _heartMintFactor,
        uint256 _maxValidBlocks
    )
        ERC1155("https://heartmint.fileverse.io/token/")
        ERC2771Context(_trustedForwarder)
    {
        require(_trustedForwarder != address(0), "HM101");
        require(_heartMintFactor != 0, "HM102");
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(PAUSER_ROLE, pauser);
        _grantRole(URI_SETTER_ROLE, minter);
        _grantRole(MINTER_ROLE, minter);
        trustedForwarder = _trustedForwarder;
        heartMintFactor = _heartMintFactor;
        maxValidBlocks = _maxValidBlocks;
    }

    function setURI(string memory newuri) public onlyRole(URI_SETTER_ROLE) {
        _setURI(newuri);
    }

    function setHeartMintFactor(uint256 _heartMintFactor)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        heartMintFactor = _heartMintFactor;
    }

    function setMaxValidBlocks(uint256 _maxValidBlocks)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        maxValidBlocks = _maxValidBlocks;
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function getCurrentTokenId() public view returns (uint256) {
        return tokenIdCounter.current();
    }

    function setUrlAndTokenId(uint256 tokenId, bytes32 url) internal {
        urlTokenMap[url] = tokenId;
        reverseUrlTokenMap[tokenId] = url;
    }

    // counter based id
    function mint(
        address account,
        uint256 startBlock,
        bytes32 urlString,
        bytes memory data
    ) public onlyRole(MINTER_ROLE) {
        uint256 timeSpent = block.number - startBlock;
        require(timeSpent < maxValidBlocks, "HM103");
        uint256 id = urlTokenMap[urlString];
        uint256 amount = timeSpent * heartMintFactor;
        if (id == 0) {
            tokenIdCounter.increment();
            id = getCurrentTokenId();
            setUrlAndTokenId(id, urlString);
        }
        _mint(account, id, amount, data);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal override(ERC1155, ERC1155Pausable, ERC1155Supply) {
        ERC1155Pausable._beforeTokenTransfer(
            operator,
            from,
            to,
            ids,
            amounts,
            data
        );
        ERC1155Supply._beforeTokenTransfer(
            operator,
            from,
            to,
            ids,
            amounts,
            data
        );
    }

    /**
     * `function _msgSender() internal view override(Context, ERC2771Context) returns (address sender)`
     *
     * @notice The function is named `_msgSender` and it is `internal` and `view` (i.e. it does not modify the
     * state of the contract and it does not cost gas). It `overrides` the `_msgSender` function in the
     * `Context` contract. It returns the address of the sender of the message
     * @dev This function is required to make the contract gasless and is inherited from ERC2771Context
     * @return sender the address of the message sender
     */
    function _msgSender()
        internal
        view
        override(Context, ERC2771Context)
        returns (address sender)
    {
        return ERC2771Context._msgSender();
    }

    /**
     * `function _msgData() internal view override(Context, ERC2771Context) returns (bytes calldata)`
     *
     * @notice The function is named `_msgData` and it is `internal` and `view` (i.e. it does not modify the
     * state of the contract and it does not cost gas). It `overrides` the `_msgData` function in the
     * `Context` contract. It returns a `bytes calldata` value
     * @dev This function is required to make the contract gasless and is inherited from ERC2771Context
     * @return The calldata of the message.
     */
    function _msgData()
        internal
        view
        override(Context, ERC2771Context)
        returns (bytes calldata)
    {
        return ERC2771Context._msgData();
    }

    function getCurrentBlockTime() public view returns (uint256) {
        return block.number;
    }
}
