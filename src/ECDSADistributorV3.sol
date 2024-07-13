// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

import {SafeERC20, IERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable2Step, Ownable} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";

//import {ReentrancyGuard} from "@looksrare/contracts-libs/contracts/ReentrancyGuard.sol";

contract ECDSADistributorV3 is EIP712, Pausable, AccessControl, Ownable2Step {
    using SafeERC20 for IERC20;

    // token
    IERC20 internal immutable TOKEN;
    uint256 public immutable TOKEN_PRECISION;     //   

    uint256 public constant PERCENTAGE_PRECISION = 1e5;     // Y.yyy%

    address internal immutable STORED_SIGNER; //note: if change, should redeploy.

    uint256 public startDate; //immutable?

    // Users can claim until this timestamp
    uint256 public deadline;
    address public operator;

    struct Claim {
        address user;
        uint256 totalAmount;         //totalTokens for all rounds
    }
    
    //mapping(uint256 round => RoundData roundData) public allRounds;
    uint256[] public startTimes;
    uint256[] public pcntReleased;       // pct values, 7211 ->  7211/percentage_precision ->  7.211%
    uint256[] public depositedTokens;
    uint256[] public claimedTokens;

    mapping(address user => uint256 claimedAmount) public claimed;
    mapping(bytes signature => bool claimed) public hasClaimed;

    uint256 public numberOfRounds;   // immutable: check probability of adding rounds   
    uint256 public lastClaimTime;   // startTime of last round

// ------ errors --------------
    error SignatureConsumed();
    error DeadlineExceeded();

    error RoundNotStarted();
    error AmountHigherThanMax();
    error RoundFullyClaimed();
    error IncorrectAmount();
    
    error InvalidSignature();
    error ECDSAZeroAddress();

    error EmptyArray();
    error IncorrectLengths();

    error IncorrectRounds();

// ----------------------------------------

// ------ events --------------
    event Claimed(address indexed user, uint256 indexed round, uint256 amount);
    event ClaimedAll(address indexed user, uint128[] indexed rounds, uint128 totalAmount);
    event DeadlineUpdated(uint256 newDeadline);
    event SetupRounds(uint256 indexed numOfRounds, uint256 indexed totalTokens, uint256 indexed lastClaimTime);
// ----------------------------------------

    constructor(string memory _name, string memory _version, address token, uint256 tokenPrecision, address storedSigner, address owner) EIP712(_name, _version) Ownable(owner) {
        
        TOKEN = IERC20(token);
        TOKEN_PRECISION = tokenPrecision;

        STORED_SIGNER = storedSigner;
    }   

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    function claim(uint256 round, uint256 totalAmount, bytes calldata signature) external whenNotPaused {

        // check that deadline as not been exceeded; if deadline has been defined
        if(deadline > 0) {
            if (block.timestamp >= deadline) {
                revert DeadlineExceeded();
            }
        }
        
        // check if signature has already been used: replay attack protection
        if (hasClaimed[signature]) revert SignatureConsumed();

        // sig.verification
        _claim(totalAmount, signature);

        // get storage: startTime + pcnt
        uint256 startTime = startTimes[round];
        uint256 pcnt = pcntReleased[round];
        uint256 depositForRound = depositedTokens[round];
        uint256 claimedForRound = claimedTokens[round];

        // check that round has begun
        if(startTime > block.timestamp) revert RoundNotStarted();

        // sanity check: round not fully claimed
        if (depositForRound == claimedForRound) revert RoundFullyClaimed(); 

        // calc. what is claimable for this round
        uint256 claimableForRound = (totalAmount * pcnt) / PERCENTAGE_PRECISION;
        if(totalAmount > claimableForRound) revert IncorrectAmount();   //sanity check

        // update round data: increment claimedTokens
        claimedTokens += claimableForRound;

        // update storage
        hasClaimed[signature] = true;
        allRounds[round] = roundData;
        
        emit Claimed(msg.sender, round, claimableForRound);

        TOKEN.safeTransfer(msg.sender, claimableForRound);
    }

    function claimMultiple(uint256[] calldata rounds, uint256 totalAmount, bytes calldata signature) external whenNotPaused {

        // check that deadline as not been exceeded; if deadline has been defined
        if(deadline > 0) {
            if (block.timestamp >= deadline) {
                revert DeadlineExceeded();
            }
        }
        
        // check if signature has already been used: replay attack protection
        if (hasClaimed[signature]) revert SignatureConsumed();

        // sig.verification
        _claim(totalAmount, signature);

        uint256 numOfRounds = rounds.length;
        if(numOfRounds == 0) revert EmptyArray(); 
        if(numOfRounds > numberOfRounds) revert IncorrectRounds();

        uint256 totalClaimable;
        for(uint256 i = 0; i < numOfRounds; ++i) {
            
            // get round no. & round data
            uint128 round = rounds[i];
            RoundData memory roundData = allRounds[round];

            // check that round has begun
            if(roundData.startTime > block.timestamp) revert RoundNotStarted();
            // sanity check: round not fully claimed
            if (roundData.depositedTokens == roundData.claimedTokens) revert RoundFullyClaimed(); 
            

            uint256 claimableForRound = (totalAmount * roundData.pcntReleased) / PERCENTAGE_PRECISION;

            // update round data: increment claimedTokens
            roundData.claimedTokens += claimableForRound;
            allRounds[round] = roundData;

            totalClaimable += claimableForRound;
        }

        //sanity check
        if(totalAmount < totalClaimable) revert IncorrectAmount();   

        // update storage: user's claimed amt
        claimed[msg.sender] += totalClaimable;

        // last round check: mark signature
        if (round == numberOfRounds) {
            hasClaimed[signature] = true;
        }

        emit ClaimedAll(msg.sender, rounds, totalClaimable);
        
        TOKEN.safeTransfer(msg.sender, totalClaimable);

    }

    function _claim(uint256 totalAmount, bytes memory signature) internal {

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(keccak256("Claim(address user,uint256 totalAmount)"), msg.sender, amount)));

        address signer = ECDSA.recover(digest, signature);
            if(signer != STORED_SIGNER) revert InvalidSignature(); 
            if(signer == address(0)) revert ECDSAZeroAddress(); // note: is this needed given the earlier
    }

}