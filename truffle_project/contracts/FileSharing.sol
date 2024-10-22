// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileSharing {
    struct File {
        string fileName;
        address owner;
        bool exists;
    }

    struct AccessRequest {
        address requester;
        bool approved;
        bool exists;
        string publicKey;  // Store the requester's public key
        bytes encryptedKey;  // Encrypted AES key (added later during approval)
    }

    mapping(string => File) public files;
    mapping(string => AccessRequest) public accessRequests;

    event FileUploaded(string fileName, address owner);
    event AccessRequested(string fileName, address requester);
    event AccessApproved(string fileName, address requester);

    // Upload a file and record it on the blockchain
    function uploadFile(string memory _fileName) public {
        require(!files[_fileName].exists, "File already exists");
        files[_fileName] = File(_fileName, msg.sender, true);
        emit FileUploaded(_fileName, msg.sender);
    }

    // Request access to a file with the requester's public key
    function requestAccess(string memory _fileName, string memory _publicKey) public {
        require(files[_fileName].exists, "File does not exist");
        accessRequests[_fileName] = AccessRequest(msg.sender, false, true, _publicKey, "");
        emit AccessRequested(_fileName, msg.sender);
    }

    // Approve access and store the encrypted AES key
    function approveAccessWithKey(string memory _fileName, bytes memory _encryptedKey) public {
        require(files[_fileName].owner == msg.sender, "Only owner can approve access");
        require(accessRequests[_fileName].exists, "Access request does not exist");

        accessRequests[_fileName].approved = true;
        accessRequests[_fileName].encryptedKey = _encryptedKey;  // Store the encrypted AES key
        emit AccessApproved(_fileName, accessRequests[_fileName].requester);
    }

    // Check if access is approved
    function isAccessApproved(string memory _fileName) public view returns (bool) {
        return accessRequests[_fileName].approved;
    }
}
