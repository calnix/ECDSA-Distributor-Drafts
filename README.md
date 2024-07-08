# Notes

## Types

1. 100% claim 
2. optional lump sum claim + uniform periodic distribution (weekly, monthly, etc)
3. option 2, but non-periodic


Have a merkle root for each claim checkpoint; regardless if its instant, partial instant + distribution.
Generalize each checkpoint to be a startTime + merkle root - this will cover all options.

Have a global deadline, so that pass this date, no claiming for any round will be allowed.
Past deadline, can owner can withdraw tokens.


```solidity

struct RoundData {
    uint256 startTime;
    bytes32 root
    // uint256 maximumAmountPerUser
    // uint256 depositedTokens
    // uint256 claimedTokens
}

uint256 public currentRound;
mapping (uint256 round => RoundData roundData) public rounds;

```

## Issue/Considerations

1. What if there are multiple rounds, and user wants to batch claim?

```solidity

 function claim(uint256 amount, bytes32[] calldata merkleProof);

 function claimAll(uint256[] calldata amounts, bytes32[][] calldata merkleProofs)

```

2. What if we don't want to deposit all the tokens at once for multiple rounds?

Want to have round-sensitive deposits. So that although round 2 has opened up, ppl can only claim for round 1.
If 2 rounds are claimable, but we only financed for the earlier round and don't want co-mingling.

```solidity 

function depositTokens(uint256 amount, uint256[] rounds)

```

This means that when depositing we must specify which round we are financing.

Project will handle financing. deposit and withdraw.
Owner can pause, unpause, whitelist(addr). deadline.

Minimise operations. 

# USE ECDSA if > 127 users - gas savings

https://x.com/Jeyffre/status/1807008534477058435