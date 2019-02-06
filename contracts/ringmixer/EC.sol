pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

// ring verification using bn256 precompiles
// in progress
contract Verify {
	struct Point {
		int256 x;
		int256 y;
	}

	// base point for bn256
	Point G = Point(1,-2); 

	function ec_mul(Point memory a, uint256 k) public returns (Point memory p) {
	  int256[3] memory input;
	  input[0] = a.x;
	  input[1] = a.y;
	  input[2] = int256(k);
	  assembly {
	    if iszero(call(not(0), 0x07, 0, input, 0x60, p, 0x40)) {
	      revert(0, 0)
	    }
	  }
	}

	function ec_base_mul(uint256 k) public returns (Point memory p) {
		return ec_mul(G, k);
	}

	function ec_add(Point memory P1, Point memory P2) public returns (Point memory p) {
		Point[2] memory input = [P1, P2];
		assembly {
			if iszero(call(gas, 0x06, 0, input, 0x80, p, 0x40)) {
				revert(0,0)
			}
		}
	}

	function ring_verify() public returns (bool) {
		return false;
	}
}