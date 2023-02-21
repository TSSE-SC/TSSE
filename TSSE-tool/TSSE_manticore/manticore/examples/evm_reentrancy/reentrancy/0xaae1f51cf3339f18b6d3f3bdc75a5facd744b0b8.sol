/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 54
 */

pragma solidity ^0.4.19;

contract DEP_BANK 
{
    mapping (address=>uint256) public balances;   
   
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        if(intitalized)throw;
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        if(intitalized)throw;
        Log = LogFile(_log);
    }
    
    function Initialized()
    public
    {
        intitalized = true;
    }
    
    function Deposit()
    public
    payable
    {
        balances[msg.sender]+= msg.value;
        Log.AddMessage(msg.sender,msg.value,"Put");
    }
    
    function Collect(uint _am)
    public
    payable
    {
        if(balances[msg.sender]>=MinSum && balances[msg.sender]>=_am)
        {
            // <yes> <report> REENTRANCY
            // if(msg.sender.call.value(_am)())
            // {
            //     balances[msg.sender]-=_am;
            //     Log.AddMessage(msg.sender,_am,"Collect");
            // }

            if (Log.AddMessage(msg.sender,_am,"Collect"))
            {
                balances[msg.sender]-=_am;
               
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Deposit();
    }
    
}


contract LogFile
{
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    
    Message LastMsg;

    address owner;

    // constructor() public{
    //     owner = msg.sender;
    // }


    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }
    
    function AddMessage(address _adr,uint _val,string _data) onlyOwner public returns (bool)
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
        return true;
    }
}