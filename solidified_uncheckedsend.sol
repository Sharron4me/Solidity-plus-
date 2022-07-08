pragma solidity ^0.8.0;
 string[] callStack;
 uint flag;
 event checkMsg(string message);
function checkReentrancy(string memory functionName) public { 
 if(callStack.length > 0){ 
 for(uint i=callStack.length; i>0; i--) { 
 if(keccak256(abi.encodePacked(callStack[i-1])) == keccak256(abi.encodePacked(functionName))) 
 flag = 0; 
 } 
 } else 
 flag = 1; 

 require(flag==1, "Possibility of reentrancy"); 
} 
;uint balance=0;function SendE(address payable receiver) public payable {
 emit checkMsg("Checking Reentrancy"); 
 checkReentrancy("SendE"");
 callStack.push(""SendE"");
require(receiver.send(msg.value), "Send Failed!!"); 
}}function() external payable{
 emit checkMsg("Checking Reentrancy"); 
 checkReentrancy("fallback");
 callStack.push("fallback");
balance = balance+msg.value;}}