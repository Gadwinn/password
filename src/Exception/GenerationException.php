<?php

declare(strict_types=1);

namespace G\Password\Exception;

use RuntimeException;

/**
 * Exception thrown when password generation cannot satisfy the provided constraints.
 */
class GenerationException extends RuntimeException
{
}
