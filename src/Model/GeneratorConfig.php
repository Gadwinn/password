<?php

declare(strict_types=1);

namespace G\Password\Model;

use G\Password\Enum\CharacterSet;
use G\Password\Exception\GenerationException;

/**
 * Immutable configuration value object for password generation.
 */
final class GeneratorConfig
{
    /** @var array<string,int> */
    private readonly array $requirements;
    /** @var CharacterSet[] */
    private readonly array $activeSets;
    private readonly int $length;
    private readonly bool $excludeAmbiguous;
    /** @var string[] */
    private readonly array $excludedCharacters;

    /**
     * @param array{length?:int,requirements?:array<string,int>,exclude_ambiguous?:bool,exclude?:string} $config
     */
    public static function fromArray(array $config): self
    {
        $length = (int)($config['length'] ?? 0);
        $requirements = $config['requirements'] ?? [];
        $excludeAmbiguous = (bool)($config['exclude_ambiguous'] ?? false);
        $excludedCharacters = [];
        if (!empty($config['exclude'])) {
            $excludedCharacters = preg_split('//u', (string)$config['exclude'], -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }

        if ($length < 1) {
            throw new GenerationException('Length must be >= 1.');
        }

        // Map requirement keys to CharacterSet enum cases if value > 0.
        $map = [
            'lower' => CharacterSet::LOWER,
            'upper' => CharacterSet::UPPER,
            'digit' => CharacterSet::DIGIT,
            'symbol' => CharacterSet::SYMBOL_BASIC,
            'symbol_extended' => CharacterSet::SYMBOL_EXTENDED,
            'accented_lower' => CharacterSet::ACCENTED_LOWER,
            'accented_upper' => CharacterSet::ACCENTED_UPPER,
        ];
        $activeSets = [];
        $minTotal = 0;
        foreach ($requirements as $key => $min) {
            /** @var string $key */
            /** @var int $min */
            $min = (int)$min;
            if ($min < 0) {
                throw new GenerationException('Requirement values must be >= 0.');
            }
            if ($min === 0) {
                continue;
            }
            if (!isset($map[$key])) {
                throw new GenerationException('Unknown requirement key: ' . $key);
            }
            $activeSets[] = $map[$key];
            $minTotal += $min;
        }
        if ($minTotal > $length) {
            throw new GenerationException('Sum of minimum requirements exceeds desired length.');
        }
        if (empty($activeSets)) {
            throw new GenerationException('At least one character set must be active.');
        }

        return new self($length, $requirements, $activeSets, $excludeAmbiguous, $excludedCharacters);
    }

    /**
     * @param array<string,int> $requirements
     * @param CharacterSet[] $activeSets
     * @param string[] $excludedCharacters
     */
    private function __construct(
        int $length,
        array $requirements,
        array $activeSets,
        bool $excludeAmbiguous,
        array $excludedCharacters
    ) {
        $this->length = $length;
        $this->requirements = $requirements;
        $this->activeSets = $activeSets;
        $this->excludeAmbiguous = $excludeAmbiguous;
        $this->excludedCharacters = $excludedCharacters;
    }

    public function length(): int
    {
        return $this->length;
    }

    /** @return array<string,int> */
    public function requirements(): array
    {
        return $this->requirements;
    }

    /** @return CharacterSet[] */
    public function activeSets(): array
    {
        return $this->activeSets;
    }

    public function excludeAmbiguous(): bool
    {
        return $this->excludeAmbiguous;
    }

    /** @return string[] */
    public function excludedCharacters(): array
    {
        return $this->excludedCharacters;
    }
}
