<?php

declare(strict_types=1);

namespace G\Password\Enum;

/**
 * Types of validation issues that can be reported.
 */
enum IssueType: string
{
    case LENGTH = 'length';
    case REQUIRED_SET_MISSING = 'required_set_missing';
    case AMBIGUOUS_PRESENT = 'ambiguous_present';
    case REPEAT_PATTERN = 'repeat_pattern';
    case SEQUENCE_PATTERN = 'sequence_pattern';
    case ENTROPY_LOW = 'entropy_low';
    case BLACKLIST = 'blacklist';
}
