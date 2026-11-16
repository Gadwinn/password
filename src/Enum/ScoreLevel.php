<?php

declare(strict_types=1);

namespace G\Password\Enum;

/**
 * Score levels for password strength assessment.
 */
enum ScoreLevel: string
{
    case NONE = 'none';
    case WEAK = 'weak';
    case FAIR = 'fair';
    case GOOD = 'good';
    case STRONG = 'strong';
}
