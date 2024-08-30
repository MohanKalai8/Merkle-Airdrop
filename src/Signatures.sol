// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SignatureVerifier {

    // Signature verification using EIP - 712

    struct EIP721Domain{
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    // Here is the hash of our EIP721 domain struct
    bytes32 constant EIPDOMAIN_TYPEHASH = keccak256("EIP721Domain(string name, string version,uint256 chainId, address verifyingContract)");

    // Here is where things get a bit hairy
    // Since we want to make sure signatures ONLY work for our contract, on our chain, with our application
    // We need to define some variables
    // Often, it's best to make these immutables so they can't ever change
    EIP721Domain eip_721_domain_separator_struct;
    bytes32 public immutable i_domain_separator;

    constructor() {
        // Here, we define what our "domain" struct looks like.
        eip_721_domain_separator_struct = EIP721Domain({
            name: "SignatureVerifier",
            version: "1",
            chainId:1,
            verifyingContract:address(this)
        });

        //  Then, we define who is going to verify our signature ? Now that we know what the format our doamin is
        i_domain_separator = keccak256(
            abi.encode(
                EIPDOMAIN_TYPEHASH,
                keccak256(bytes(eip_721_domain_separator_struct.name)),
                keccak256(bytes(eip_721_domain_separator_struct.version)),
                eip_721_domain_separator_struct.chainId,
                eip_721_domain_separator_struct.verifyingContract
            )
        );
    }

    // THEN we need to define what our message hash struct looks like.
    struct Message {
        uint256 number;
    }

    bytes32 public constant MESSAGE_TYPEHASH = keccak256("Message(uint256 number)");

    function getSignerEIP712(uint256 message,uint8 _v, bytes32 _r, bytes32 _s) public view returns(address){
        // Arguments when calculation hash to validate
        // 1: bytes(0x19) - the initial 0x19 byte
        // 2: bytes(1) - the version byte
        // 3: hashstruct of domain separator (includes the typehash of the domain struct)
        // 4: hashstruct of message (includes the typehash of the message struct)

        // bytes32 memory prefix = "\x19Ethereum Signed Message:\n32";
        // bytes32 prefixedHashMessage = kacck256(abi.encodePacked(prefix,nonces[msg.sender], _hashedMessage));
        // require(msg.sender == signer);
        // return signer;

        bytes1 prefix = bytes1(0x19);
        bytes1 eip712Version = bytes1(0x01); // EIP-712 is version 1 of EIP-191
        bytes32 hashStructOfDomainSeparator = i_domain_separator;

        // now, we can hash our message struct
        bytes32 hashedMessage = keccak256(abi.encode(MESSAGE_TYPEHASH,Message({number:message})));

        // And finally, combine them all
        bytes32 digest = keccak256(abi.encodePacked(prefix,eip712Version,hashStructOfDomainSeparator,hashedMessage));
        return ecrecover(digest, _v,_r,_s);
    }



    function getSigner(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes32 hashedMessage = bytes32(message); // if string we use keccack256(abi.encodePacked(string))
        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }

    function verifyMessage(uint256 message, uint8 _v, bytes32 _r, bytes32 _s, address signer)
        public
        pure
        returns (bool)
    {
        address actualSigner = getSigner(message, _v, _r, _s);
        require(signer == actualSigner);
        return true;
    }

    // Signature verification using EIP-191
    function getSigner191(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public view returns (address) {
        // Arguments when calculation hash to validate
        // 1: bytes(0x19) - the initial 0x19 bytes
        // 2: bytes(0) - the version bytes
        // 3: version specific data, for version 0, it's the intended validator address
        // 4-6: Application specific data

        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0);
        address intendedValidatorAddress = address(this);
        bytes32 applicationSpecificData = bytes32(message);

        // 0x19 <1 byte version > <version specific data> <data to sign>
        bytes32 hashedMessage =
            keccak256(abi.encodePacked(prefix, eip191Version, intendedValidatorAddress, applicationSpecificData));

        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }

}
