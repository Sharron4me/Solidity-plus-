pragma solidity ^0.8.0;

contract SendEther {
    uint balance=0;
    function SendE(address payable receiver) public payable {
        receiver.send(msg.value);
    }
    function() external payable{
    	balance = balance+msg.value;
    }
}
