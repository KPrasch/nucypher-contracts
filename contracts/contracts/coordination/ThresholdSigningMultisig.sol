// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import "./IThresholdSigningMultisig.sol";

contract ThresholdSigningMultisig is
    IThresholdSigningMultisig,
    Initializable,
    IERC1271,
    OwnableUpgradeable
{
    using ECDSA for bytes32;
    using ERC4337Utils for PackedUserOperation;

    event Executed(
        address indexed sender,
        uint256 indexed nonce,
        address indexed destination,
        uint256 value
    );
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event SignerReplaced(address indexed signer, address newSigner);
    event SignedMessageCached(bytes32 indexed hash);
    event ThresholdChanged(uint16 threshold);

    uint256 public constant MAX_SIGNER_COUNT = 40;

    uint256 public nonce;
    mapping(address => bool) public isSigner;
    address[] public signers;
    uint16 public threshold;

    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;
    mapping(bytes32 => bytes32) public validSignatures;

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address[] memory _signers,
        uint16 _threshold,
        address _initialOwner
    ) public initializer {
        require(owner() == address(0), "Already initialized");
        __Ownable_init(_initialOwner);
        require(
            _signers.length <= MAX_SIGNER_COUNT &&
            _threshold <= _signers.length &&
            _threshold > 0,
            "Invalid arguments"
        );

        for (uint256 i = 0; i < _signers.length; i++) {
            address signer = _signers[i];
            require(!isSigner[signer] && signer != address(0), "Not already a signer");
            isSigner[signer] = true;
        }
        nonce = 1;
        signers = _signers;
        threshold = _threshold;
    }

function execute(PackedUserOperation calldata userOp) external {
    require(userOp.sender == msg.sender, "Invalid sender");
    bytes32 userOpHash = ERC4337Utils.hash(
        userOp,
        address(ERC4337Utils.ENTRYPOINT_V08)
    );
    require(
        isValidSignature(userOpHash, userOp.signature) == MAGICVALUE,
        "Invalid Signature"
    );

    (address destination, uint256 value, bytes memory data) =
        abi.decode(userOp.callData, (address, uint256, bytes));

    emit Executed(userOp.sender, userOp.nonce, destination, value);
    nonce++;

    (bool success, ) = destination.call{value: value}(data);
    require(success, "Transaction failed");
}

    function isValidSignature(
        bytes32 _hash,
        bytes memory _signature
    ) public view override returns (bytes4) {
        require(
            _signature.length >= threshold * 65,
            "Invalid threshold of signatures"
        );
        if (validSignatures[_hash] == keccak256(_signature)) {
            return MAGICVALUE;
        }

        address lastSigner = address(0);
        for (uint16 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(_signature, i);
            address recovered = ecrecover(_hash, v, r, s);
            if (!isSigner[recovered] || recovered <= lastSigner) {
                return INVALID_SIGNATURE;
            }
            lastSigner = recovered;
        }

        return MAGICVALUE;
    }

    function signatureSplit(
        bytes memory signatures,
        uint256 pos
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        /// @solidity memory-safe-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }

    function addSigner(address _signer) public onlyOwner {
        require(signers.length < MAX_SIGNER_COUNT, "At max signers");
        require(_signer != address(0) && !isSigner[_signer], "Invalid signer");
        signers.push(_signer);
        isSigner[_signer] = true;
        emit SignerAdded(_signer);
    }

    function removeSigner(address _signer) public onlyOwner {
        require(signers.length > threshold && isSigner[_signer], "Invalid signer");
        isSigner[_signer] = false;

        uint256 index = signers.length;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == _signer) {
                index = i;
                break;
            }
        }
        require(index < signers.length, "Signer not found");
        signers[index] = signers[signers.length - 1];
        signers.pop();
        emit SignerRemoved(_signer);
    }

    function replaceSigner(address oldSigner, address newSigner) public onlyOwner {
        require(isSigner[oldSigner] && !isSigner[newSigner], "Invalid Signer");
        removeSigner(oldSigner);
        addSigner(newSigner);
        emit SignerReplaced(oldSigner, newSigner);
    }

    function getSigners() public view returns (address[] memory) {
        return signers;
    }

    function changeThreshold(uint16 _threshold) public onlyOwner {
        require(_threshold <= signers.length && _threshold > 0, "Invalid threshold");
        threshold = _threshold;
        emit ThresholdChanged(_threshold);
    }

    function saveSignature(bytes32 _hash, bytes memory _signature) public {
        require(
            isValidSignature(_hash, _signature) == MAGICVALUE,
            "Invalid Signature"
        );
        validSignatures[_hash] = keccak256(_signature);
        emit SignedMessageCached(_hash);
    }
}
