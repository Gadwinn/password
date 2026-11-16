<?php

declare(strict_types=1);

namespace G\Password\Model;

use G\Password\Exception\ValidationException;

/**
 * Immutable validation rules value object.
 */
final class ValidationRules
{
    private readonly int $minLength;
    private readonly int $maxLength;
    /** @var array<string,int> */
    private readonly array $requirements;
    private readonly bool $excludeAmbiguous;
    /** @var string[] */
    private readonly array $blacklist;
    /** @var string[] */
    private readonly array $excludedCharacters;
    private readonly float $attemptsPerSecond;

    public const int DEFAULT_MIN_LENGTH = 8;
    public const float DEFAULT_ATTEMPTS_PER_SECOND = 1_000_000_000.0;

    /**
     * @param array{
     *   min_length?:int,
     *   max_length?:int,
     *   requirements?:array<string,int>,
     *   exclude_ambiguous?:bool,
     *   blacklist?:string[],
     *   exclude?:string,
     *   attempts_per_second?:float
     * } $rules
     */
    public static function fromArray(array $rules): self
    {
        $minLength = (int)($rules['min_length'] ?? self::DEFAULT_MIN_LENGTH);
        $maxLength = (int)($rules['max_length'] ?? 0);
        $requirements = $rules['requirements'] ?? [];
        $excludeAmbiguous = (bool)($rules['exclude_ambiguous'] ?? false);
        $blacklist = $rules['blacklist'] ?? [];
        $excluded = [];
        if (!empty($rules['exclude'])) {
            $excluded = preg_split('//u', (string)$rules['exclude'], -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }
        $attemptsPerSecond = (float)($rules['attempts_per_second'] ?? self::DEFAULT_ATTEMPTS_PER_SECOND);

        if ($minLength < 1) {
            throw new ValidationException('Minimum length must be >= 1.');
        }
        if ($maxLength !== 0 && $maxLength < $minLength) {
            throw new ValidationException('max_length must be >= min_length or 0 for unlimited.');
        }
        foreach ($requirements as $k => $v) {
            if ((int)$v < 0) {
                throw new ValidationException('Requirement values must be >= 0.');
            }
        }
        return new self(
            $minLength,
            $maxLength,
            $requirements,
            $excludeAmbiguous,
            $blacklist,
            $excluded,
            $attemptsPerSecond
        );
    }

    /**
     * @param array<string,int> $requirements
     * @param string[] $blacklist
     * @param string[] $excludedCharacters
     */
    private function __construct(
        int $minLength,
        int $maxLength,
        array $requirements,
        bool $excludeAmbiguous,
        array $blacklist,
        array $excludedCharacters,
        float $attemptsPerSecond
    ) {
        $this->minLength = $minLength;
        $this->maxLength = $maxLength;
        $this->requirements = $requirements;
        $this->excludeAmbiguous = $excludeAmbiguous;
        $this->blacklist = $blacklist;
        $this->excludedCharacters = $excludedCharacters;
        $this->attemptsPerSecond = $attemptsPerSecond;
    }

    public function minLength(): int
    {
        return $this->minLength;
    }
    public function maxLength(): int
    {
        return $this->maxLength;
    }
    /** @return array<string,int> */
    public function requirements(): array
    {
        return $this->requirements;
    }
    public function excludeAmbiguous(): bool
    {
        return $this->excludeAmbiguous;
    }
    /** @return string[] */
    public function blacklist(): array
    {
        return $this->blacklist;
    }
    /** @return string[] */
    public function excludedCharacters(): array
    {
        return $this->excludedCharacters;
    }
    public function attemptsPerSecond(): float
    {
        return $this->attemptsPerSecond;
    }
}
