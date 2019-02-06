pragma solidity ^0.5.0;

contract RingVerify {
    event Verify(bool indexed ok);

    function verify(bytes memory _sig) public returns (bool) {
        bool ok;

        // precompile for verify located at address 0x09
        address _a = address(9);
        uint256 _len = _sig.length + 32;
        uint256 _gas = 1000;

        assembly {            
            let x := mload(0x40) // get empty storage location

            let ret := call(_gas, 
                _a,
                0, // no wei value passed to function
                _sig, // input
                _len, // input size
                x, // output stored at input location, save space
                0x20 // output size = 32 bytes
            )
                
            ok := mload(x)
            mstore(0x40, add(x,0x20)) // update free memory pointer
        }

        emit Verify(ok);
        return ok;
    }
}