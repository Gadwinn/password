<?php

declare(strict_types=1);

namespace G\Password\Model;

use G\Password\Enum\ScoreLevel;

/**
 * Aggregated result of password validation.
 */
final class ValidationResult
{
    /** @var ValidationIssue[] */
    private array $issues = [];
    /** @var array<string,int> */
    private array $counts = [];

    public function __construct(
        private bool $valid,
        private ScoreLevel $score,
        private float $entropyBits,
        private float $entropyBitsTheoretical,
        private float $crackTimeSeconds,
        private int $length
    ) {
    }

    public function addIssue(ValidationIssue $issue): void
    {
        $this->issues[] = $issue;
    }

    /**
     * @param array<string,int> $counts
     */
    public function setCounts(array $counts): void
    {
        $this->counts = $counts;
    }

    public function isValid(): bool
    {
        return $this->valid;
    }
    public function score(): ScoreLevel
    {
        return $this->score;
    }
    public function entropyBits(): float
    {
        return $this->entropyBits;
    }

    public function entropyBitsTheoretical(): float
    {
        return $this->entropyBitsTheoretical;
    }

    public function crackTimeSeconds(): float
    {
        return $this->crackTimeSeconds;
    }
    public function length(): int
    {
        return $this->length;
    }
    /** @return ValidationIssue[] */
    public function issues(): array
    {
        return $this->issues;
    }
    /** @return array<string,int> */
    public function counts(): array
    {
        return $this->counts;
    }
}
