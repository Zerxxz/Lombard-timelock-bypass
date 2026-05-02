// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title Use for Consortium
 * @author Lombard.Finance
 * @notice The contract is a part of the Lombard.Finance protocol.
 *         Executor is EOA controlled by decentralized consortium consensus mechanism.
 * @dev    This contract hardcodes `admin = address(0)` in the constructor,
 *         which creates a governance lock-in: no one can ever grant roles.
 *         If this contract were deployed with a real admin address (as the
 *         underlying OZ TimelockController allows), that admin would gain
 *         instant, timelock-bypassing control.
 */
contract LombardTimeLock is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors
    ) TimelockController(minDelay, proposers, executors, address(0)) {}
}
