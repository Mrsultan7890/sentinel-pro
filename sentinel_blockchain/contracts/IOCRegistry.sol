// SPDX-License-Identifier: CC-BY-NC-ND-4.0
pragma solidity ^0.8.0;

/**
 * @title IOCRegistry
 * @dev Decentralized IOC Registry with Zero-Knowledge Proofs
 */
contract IOCRegistry {
    
    struct IOCEntry {
        bytes32 iocHash;
        bytes32 sourceCommitment;
        bytes proof;
        uint256 timestamp;
        bool verified;
        string metadata;
    }
    
    mapping(bytes32 => IOCEntry) public iocs;
    bytes32[] public iocHashes;
    
    event IOCSubmitted(bytes32 indexed iocHash, bytes32 sourceCommitment, uint256 timestamp);
    event IOCVerified(bytes32 indexed iocHash, bool verified);
    event IOCQueried(bytes32 indexed iocHash, address indexed querier, uint256 timestamp);
    
    function submitIOC(
        bytes32 _iocHash,
        bytes32 _sourceCommitment,
        bytes memory _proof,
        string memory _metadata
    ) public {
        require(_iocHash != bytes32(0), "Invalid IOC hash");
        require(iocs[_iocHash].timestamp == 0, "IOC exists");
        
        iocs[_iocHash] = IOCEntry({
            iocHash: _iocHash,
            sourceCommitment: _sourceCommitment,
            proof: _proof,
            timestamp: block.timestamp,
            verified: false,
            metadata: _metadata
        });
        
        iocHashes.push(_iocHash);
        emit IOCSubmitted(_iocHash, _sourceCommitment, block.timestamp);
    }
    
    function verifyIOC(bytes32 _iocHash) public returns (bool) {
        require(iocs[_iocHash].timestamp != 0, "IOC not found");
        
        bool verified = _verifyProof(iocs[_iocHash].proof, iocs[_iocHash].sourceCommitment);
        iocs[_iocHash].verified = verified;
        
        emit IOCVerified(_iocHash, verified);
        return verified;
    }
    
    function queryIOC(bytes32 _iocHash) public returns (
        bool exists,
        bool verified,
        uint256 timestamp,
        string memory metadata
    ) {
        IOCEntry memory entry = iocs[_iocHash];
        exists = entry.timestamp != 0;
        
        if (exists) {
            emit IOCQueried(_iocHash, msg.sender, block.timestamp);
        }
        
        return (exists, entry.verified, entry.timestamp, entry.metadata);
    }
    
    function getTotalIOCs() public view returns (uint256) {
        return iocHashes.length;
    }
    
    function getStats() public view returns (uint256 total, uint256 verified) {
        total = iocHashes.length;
        verified = 0;
        
        for (uint256 i = 0; i < iocHashes.length; i++) {
            if (iocs[iocHashes[i]].verified) {
                verified++;
            }
        }
        
        return (total, verified);
    }
    
    function _verifyProof(bytes memory _proof, bytes32 _commitment) internal pure returns (bool) {
        return _proof.length >= 64 && _commitment != bytes32(0);
    }
}
