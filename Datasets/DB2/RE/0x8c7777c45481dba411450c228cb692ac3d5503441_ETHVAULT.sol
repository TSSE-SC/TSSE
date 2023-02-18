/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 41
 */
 
pragma solidity ^0.4.19;

contract ETHVAULT
{
    mapping (address => uint) public balances;
    
    Log TransferLog;
    LogFile LogF;
    
    uint public MinDeposit = 1 ether;

    uint a;
    
    function ETH_VAULT(address _log,address _log1)
    public 
    {
        TransferLog = Log(_log);
        LogF = LogFile(_log1);
    }
    
    function Deposit()
    public
    payable
    {
        if(msg.value > MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
        }
    }
    
    function CashOut(uint _am)
    public
    payable
    {
        if(_am<=balances[msg.sender])
        {
            // <yes> <report> REENTRANCY
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                a = LogF.testTarget(_am);
            }
        }
    }
    
    function() public payable{}    
    
}

contract Log 
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
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}

contract LogFile {
        
    uint w ;

    function testTarget(uint input) public returns(uint) {
        w = input;
        return w;
    }
}