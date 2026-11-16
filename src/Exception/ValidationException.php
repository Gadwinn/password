<?php

declare(strict_types=1);

namespace G\Password\Exception;

use RuntimeException;

/**
 * Exception thrown when validation rules are malformed or inconsistent.
 */
class ValidationException extends RuntimeException
{
}
