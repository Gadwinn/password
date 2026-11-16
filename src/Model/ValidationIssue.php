<?php

declare(strict_types=1);

namespace G\Password\Model;

use G\Password\Enum\IssueType;

/**
 * Represents a single validation issue with metadata for reporting.
 */
final class ValidationIssue
{
    /**
     * @param array<string,mixed> $data
     */
    public function __construct(
        public readonly IssueType $type,
        public readonly string $message,
        public readonly array $data = []
    ) {
    }
}
