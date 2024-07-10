// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

import {SafeERC20, IERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable2Step, Ownable} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";

//import {ReentrancyGuard} from "@looksrare/contracts-libs/contracts/ReentrancyGuard.sol";

contract ECDSADistributor is EIP712, Pausable, AccessControl, Ownable2Step {
    using SafeERC20 for IERC20;

    IERC20 internal immutable TOKEN;
    address internal immutable STORED_SIGNER; //note: if change, should redeploy.

    // Users can claim until this timestamp
    uint256 public deadline;
    address public operator;

    struct Claim {
        address user;
        uint128 round;
        uint128 amount;
    }
    
    struct RoundData {
        uint128 startTime;
        uint128 maxAmountPerUser;
        uint128 depositedTokens;
        uint128 claimedTokens;
    }

    mapping(uint256 round => RoundData roundData) public allRounds;
    mapping(bytes signature => bool claimed) public hasClaimed;

    uint256 public maxRounds;       // num. of rounds
    uint256 public lastClaimTime;   // startTime of last round

    // errors
    error AlreadyClaimed();
    error RoundNotStarted();
    error ClaimPeriodEnded();
    error AmountHigherThanMax();
    error RoundFullyClaimed();
    
    error InvalidSignature();
    error ECDSAZeroAddress();

    error EmptyArray();
    error IncorrectLengths();

    // events
    event Claimed(address indexed user, uint128 indexed round, uint128 amount);
    event ClaimedAll(address indexed user, uint128[] indexed rounds, uint128 totalAmount);
    event DeadlineUpdated(uint256 newDeadline);
    event SetupRounds(uint256 indexed numOfRounds, uint256 indexed totalTokens, uint256 indexed lastClaimTime);

    constructor(string memory _name, string memory _version, address token, address storedSigner, address owner) EIP712(_name, _version) Ownable(owner) {
        
        TOKEN = IERC20(token);
        STORED_SIGNER = storedSigner;
    }   

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    function claim(uint128 round, uint128 amount, bytes calldata signature) external whenNotPaused {
        
        // check that signature has already been used: replay attack protection
        if (hasClaimed[signature]) revert AlreadyClaimed();

        // check that deadline as not been exceeded; if deadline has been defined
        if(deadline > 0) {
            if (block.timestamp >= deadline) {
                revert ClaimPeriodEnded();
            }
        }
        
        RoundData memory roundData = allRounds[round];

        // check that round has begun
        if(roundData.startTime > block.timestamp) revert RoundNotStarted();

        // sanity check: max amt per user
        if (amount > roundData.maxAmountPerUser) revert AmountHigherThanMax();

        // sanity check: round not fully claimed
        if (roundData.depositedTokens == roundData.claimedTokens) revert RoundFullyClaimed(); 

        // sig.verification
        _claim(round, amount, signature);

        // update round data: increment claimedTokens
        roundData.claimedTokens += amount;

        // update storage
        hasClaimed[signature] = true;
        allRounds[round] = roundData;
        
        emit Claimed(msg.sender, round, amount);

        TOKEN.safeTransfer(msg.sender, amount);
    }

    function claimAll(uint128[] calldata rounds, uint128[] calldata amounts, bytes[] calldata signatures) external whenNotPaused {

        // check that deadline as not been exceeded; if deadline has been defined
        if(deadline > 0) {
            if (block.timestamp >= deadline) {
                revert ClaimPeriodEnded();
            }
        }
        
        uint256 roundsLength = rounds.length;
        uint256 amountsLength = amounts.length;
        uint256 signaturesLength = signatures.length;

        if(roundsLength == amountsLength && roundsLength == signaturesLength) revert IncorrectLengths(); 
        if(roundsLength == 0) revert EmptyArray(); 

        uint128 totalAmount;
        for(uint256 i = 0; i < roundsLength; ++i) {
            
            // get round no. & round data
            uint128 round = rounds[i];
            uint128 amount = amounts[i];
            bytes memory signature = signatures[i];

            RoundData memory roundData = allRounds[round];

            // check that signature has already been used: replay attack protection
            if (hasClaimed[signature]) revert AlreadyClaimed();

            // check that round has begun
            if(roundData.startTime > block.timestamp) revert RoundNotStarted();

            // sanity check: max amt per user
            if (amount > roundData.maxAmountPerUser) revert AmountHigherThanMax();

            // sanity check: round not fully claimed
            if (roundData.depositedTokens == roundData.claimedTokens) revert RoundFullyClaimed(); 

            // sig.verification
            _claim(round, amount, signature);
        
            // update round data: increment claimedTokens
            roundData.claimedTokens += amount;
            totalAmount += amount;       

            // update storage: signature + roundData
            hasClaimed[signature] = true; 
            allRounds[round] = roundData;
        }
        
        emit ClaimedAll(msg.sender, rounds, totalAmount);

        TOKEN.safeTransfer(msg.sender, totalAmount);
    }

    function _claim(uint128 round, uint128 amount, bytes memory signature) internal {

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(keccak256("Claim(address user,uint128 round,uint128 amount)"), msg.sender, round, amount)));

        address signer = ECDSA.recover(digest, signature);
            if(signer != STORED_SIGNER) revert InvalidSignature(); 
            if(signer == address(0)) revert ECDSAZeroAddress(); // note: is this needed given the earlier
    }

    // note: only callable once?
    function setupRounds(uint128[] calldata startTimes, uint128[] calldata maxAmountPerUsers, uint128[] calldata depositedTokens) external onlyOwner {

        uint256 startTimesLength = startTimes.length;
        uint256 maxAmountPerUsersLength = maxAmountPerUsers.length;
        uint256 depositedTokensLength = depositedTokens.length;

        if(startTimesLength == maxAmountPerUsersLength && startTimesLength == depositedTokensLength) revert IncorrectLengths(); 
        if(startTimesLength == 0) revert EmptyArray(); 

        uint256 totalAmount;
        for(uint256 i = 0; i < roundsLength; ++i) {

            uint128 startTime = startTimes[i];
            uint128 maxAmountPerUser = maxAmountPerUsers[i];
            uint128 depositedToken = depositedTokens[i];
            
            RoundData memory roundData = RoundData({startTime: startTime, maxAmountPerUser: maxAmountPerUser, depositedToken: depositedToken});

            totalTokens += depositedToken;

            // update mapping
            allRounds[i] = roundData;
        }

        // update
        maxRounds = startTimesLength;
        lastClaimTime = startTimes[startTimesLength-1];

        emit SetupRounds(startTimesLength, totalTokens, startTime[startTimesLength-1]);

    }

    //note: deadline must be after last claim round?
    function updateDeadline(uint256 newDeadline) external onlyOwner {
        require(block.timestamp < newDeadline, "Invalid deadline");

        // check last claim time
        lastRoundIndex = maxRounds - 1;
        allRounds[]


        deadline = newDeadline;
        emit DeadlineUpdated(newDeadline);
    }

    function updateRoundData() external onlyOwner {
        
    }

    function deposit() external {
        require(msg.sender == operator, "Incorrect caller");
    }

    function withdraw() external {
        require(msg.sender == operator, "Incorrect caller");

    }

    // project stupid then finance to wrong round, need to take out and resend - how?


    /*//////////////////////////////////////////////////////////////
                                PAUSABLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pause claim
     */
    function pause() external onlyOwner whenNotPaused {
        _pause();
    }

    /**
     * @notice Unpause claim
     */
    function unpause() external onlyOwner whenPaused {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                                RECOVERY
    //////////////////////////////////////////////////////////////*/


}


/**

    Permit
    - spender presents a signature requesting funds from John's wallet
    - did John sign the signature? if he did, allow. 

    John signs message off-chain, DApp transmits the signature via txn and handles the asset flow.
    John pays no gas.

    Similarly in Airdrop,

    - claimer presents a signature: amount, address
    - did 'we' contract signer, sign said msg?

    Have a specific EOA sign to create all signatures.
    Store addr of signer on contract
    Recover signer from signature to verify against on-chain copy.

    If attacker submits spoofed signature, incorrect signer will be returned. 
    If the correct signature was supplied by the FE, the correct signer will be returned.

*/

/**
    Attacks

    1. replay attack on other chain/contract:
        other chain - check mocaToken and hashTypedDataV4
    2. 
 */