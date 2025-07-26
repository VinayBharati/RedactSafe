// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SmartContract {
    struct UserRecord {
        string data;
        uint256 timestamp;
    }
    
    UserRecord public user_registration;
    UserRecord public access_control;
    UserRecord public permission;
       
    // Call this function to register user details data to Blockchain with current timestamp
    function setSignup(string memory ur) public {
       user_registration = UserRecord(ur, block.timestamp);	
    }
    
    // Get register details and timestamp
    function getSignup() public view returns (string memory, uint256) {
        return (user_registration.data, user_registration.timestamp);
    }

    // Call this function to manage access details in Blockchain with current timestamp
    function setAccess(string memory ac) public {
       
       access_control = UserRecord(ac, block.timestamp);	
    }
    
    // Get access control details and timestamp
    function getAccess() public view returns (string memory, uint256) {
        return (access_control.data, access_control.timestamp);
    }

    // Call this function to manage permission details in Blockchain with current timestamp
    function setPermission(string memory per) public {
       permission = UserRecord(per, block.timestamp);	
    }
    
    // Get permission details and timestamp
    function getPermission() public view returns (string memory, uint256) {
        return (permission.data, permission.timestamp);
    }
}