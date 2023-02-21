contract Test2{
    uint goal_ = 0;
    function bug_intou_inter(Test1 t1, uint b) public returns (uint){
        // goal_ = b + goal_ ; 
        // goal_ = t1.getGoal();
        goal_ += b; 
        t1.getGoal();

        // selfdestruct(msg.sender);
        // if(3000 > goal_) {
        //     goal_ = b + goal_ ;  // overflow bug inter contract
        //     selfdestruct(msg.sender);
        // }
    }
}

contract Test1{
    uint public goal = 5000;
    function getGoal() public returns(uint){
        return goal;
    }
}

// contract Test2{
//     uint goal_ = 0;

//     function bug_intou_inter(Test1 t1,uint b) public returns (uint){
//         // goal_ = b + goal_ ; 
//         goal_ = t1.getGoal();

//         goal_ += b; 
//     //     selfdestruct(msg.sender);
//     //     if(3000 > goal_) {
//     //         goal_ = b + goal_ ;  // overflow bug inter contract
//     //         selfdestruct(msg.sender);
//     //     }
//     }
// }