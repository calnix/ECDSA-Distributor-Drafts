// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {SafeERC20, IERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable2Step, Ownable} from "./../lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {Pausable} from "./../lib/openzeppelin-contracts/contracts/utils/Pausable.sol";
//import {ReentrancyGuard} from "@looksrare/contracts-libs/contracts/ReentrancyGuard.sol";

contract ProtocolFeesDistributor is Pausable, AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    address public immutable TOKEN;
    uint256 public immutable TOKEN_DECIMALS;

    // Current round (users can only claim pending protocol fees for the current round)
    uint256 public currentRound;

    // Users can claim until this timestamp
    uint256 public deadline;

    // Max amount per user in current tree
    uint256 public maximumAmountPerUserInCurrentTree;

    // Total amount claimed by user (in ETH)
    mapping(address => uint256) public amountClaimedByUser;

    // Merkle root for a round
    mapping(uint256 => bytes32) public merkleRootOfRound;

    // Keeps track on whether user has claimed at a given round
    mapping(uint256 => mapping(address => bool)) public hasUserClaimedForRound;

    event TokensClaimed(address indexed user, uint256 indexed round, uint256 amount);
    event DeadlineUpdated(uint256 timestamp);
    event ProtocolFeesDistributionUpdated(uint256 indexed round);

    error AlreadyClaimed();
    error AmountHigherThanMax();
    error ClaimPeriodEnded();
    error InvalidProof();

    /**
     * @notice Constructor
     * @param owner address of the owner
     * @param operator address of the operator
     */
    constructor(address owner, address operator, uint256 deadline_, ) {

        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        _grantRole(OPERATOR_ROLE, owner);
        _grantRole(OPERATOR_ROLE, operator);

        deadline = deadline_;
    }

    /**
     * @notice Claim pending protocol fees
     * @param amount amount to claim
     * @param merkleProof array containing the merkle proof
     */
    function claim(uint256 amount, bytes32[] calldata merkleProof) external whenNotPaused /*nonReentrant*/ {

        // check that round has not been fully claimed
        if (hasUserClaimedForRound[currentRound][msg.sender]) {
            revert AlreadyClaimed();
        }

        // check that deadline as not been exceeded
        if (block.timestamp >= deadline) {
            revert ClaimPeriodEnded();
        }

        (bool claimStatus, uint256 adjustedAmount) = _canClaim(msg.sender, amount, merkleProof);

        if (!claimStatus) {
            revert InvalidProof();
        }
        if (amount > maximumAmountPerUserInCurrentTree) {
            revert AmountHigherThanMax();
        }

        // Set mapping for user and round as true
        hasUserClaimedForRound[currentRound][msg.sender] = true;

        // Adjust amount claimed
        amountClaimedByUser[msg.sender] += adjustedAmount;

        emit TokensClaimed(msg.sender, currentRound, adjustedAmount);

        // Transfer adjusted amount
        TOKEN.safeTransfer(msg.sender, adjustedAmount);
    }

    /**
     * @notice Update distribution by adding a round with a new merkle root
     * @dev It automatically increments the currentRound
     * @param merkleRoot root of the computed merkle tree
     */
    function updateRound(bytes32 merkleRoot, uint256 newMaximumAmountPerUser) external payable whenPaused onlyRole(OPERATOR_ROLE) {
        // increment 
        currentRound++;
        
        // store
        merkleRootOfRound[currentRound] = merkleRoot;
        maximumAmountPerUserInCurrentTree = newMaximumAmountPerUser;

        emit ProtocolFeesDistributionUpdated(currentRound);
    }

    //note: update deadline
    function updateDeadline(uint256 timestamp) external onlyRole(OPERATOR_ROLE) {
    //    require(block.timestamp < timestamp, "Invalid time");

        deadline = timestamp;
        emit DeadlineUpdated(timestamp);
    }

    /**
     * @notice Check whether it is possible to claim and how much based on previous distribution
     * @param user address of the user
     * @param amount amount to claim
     * @param merkleProof array with the merkle proof
     */
    function canClaim(address user, uint256 amount, bytes32[] calldata merkleProof) external view returns (bool, uint256) {
        if (block.timestamp >= canClaimUntil) {
            return (false, 0);
        }

        return _canClaim(user, amount, merkleProof);
    }

    /**
     * @notice Check whether it is possible to claim and how much based on previous distribution
     * @dev OZ's merkle trees are based on double hashes leaves
     * @param user address of the user
     * @param amount amount to claim
     * @param merkleProof array with the merkle proof
     */
    function _canClaim(address user, uint256 amount, bytes32[] calldata merkleProof) internal view returns (bool, uint256) {
        // Compute the node and verify the merkle proof
        bytes32 node = keccak256(bytes.concat(keccak256(abi.encode(user, amount))));

        bool canUserClaim = MerkleProof.verify(merkleProof, merkleRootOfRound[currentRound], node);

        // if userCannotClaim OR user has claimed in full
        if ((!canUserClaim) || (hasUserClaimedForRound[currentRound][user])) {
            return (false, 0);

        } else {
            return (true, amount - amountClaimedByUser[user]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                PAUSABLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pause claim
     */
    function pause() external onlyRole(OPERATOR_ROLE) whenNotPaused {
        _pause();
    }

    /**
     * @notice Unpause claim
     */
    function unpause() external onlyRole(OPERATOR_ROLE) whenPaused {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                                RECOVERY
    //////////////////////////////////////////////////////////////*/

    
}
