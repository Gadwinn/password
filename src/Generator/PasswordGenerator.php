<?php

declare(strict_types=1);

namespace G\Password\Generator;

use G\Password\Enum\CharacterSet;
use G\Password\Exception\GenerationException;
use G\Password\Model\GeneratorConfig;
use G\Password\Support\SecureRandom;

/**
 * Generates secure passwords based on configuration (cryptographically secure).
 */
final class PasswordGenerator
{
    /**
     * Generate a password using the provided config array.
     * Config format example:
     * [
     *   'length' => 16,
     *   'requirements' => [ 'lower' => 1, 'upper' => 1, 'digit' => 1, 'symbol' => 1 ],
     *   'exclude_ambiguous' => true,
     *   'exclude' => "{}"
     * ]
     * @param array{length?:int,requirements?:array<string,int>,exclude_ambiguous?:bool,exclude?:string} $config
     *
     * @throws GenerationException When the configuration cannot produce a password
     */
    public function generate(array $config): string
    {
        $cfg = GeneratorConfig::fromArray($config);

        $perSetMin = $cfg->requirements();
        $length = $cfg->length();
        $activeSets = $cfg->activeSets();
        $excludeAmbiguous = $cfg->excludeAmbiguous();
        $excludedCharacters = $cfg->excludedCharacters();

        // Build character pools per set.
        $setPools = [];
        foreach ($activeSets as $set) {
            $chars = $set->characters();
            if ($excludeAmbiguous) {
                $chars = array_values(array_diff($chars, CharacterSet::ambiguousCharacters()));
            }
            if ($excludedCharacters) {
                $chars = array_values(array_diff($chars, $excludedCharacters));
            }
            if (empty($chars)) {
                throw new GenerationException('Character set became empty after exclusions: ' . $set->value);
            }
            $setPools[$set->value] = $chars;
        }
        // Combined pool (the sets do not overlap).
        $combined = array_merge(...array_values($setPools));

        $passwordChars = [];
        // Satisfy minimum requirements first.
        foreach ($perSetMin as $key => $min) {
            /** @var int $min */
            $min = (int)$min;
            if ($min <= 0) {
                continue;
            }
            /** @var string $key */
            $set = self::mapRequirementKey($key);
            if (!$set || !isset($setPools[$set->value])) {
                continue; // Skip unknown or inactive sets (already validated earlier).
            }
            $pool = $setPools[$set->value];
            for ($i = 0; $i < $min; $i++) {
                $passwordChars[] = $pool[SecureRandom::int(count($pool))];
            }
        }
        // Fill remaining length.
        while (count($passwordChars) < $length) {
            $passwordChars[] = $combined[SecureRandom::int(count($combined))];
        }
        // Shuffle final characters.
        /** @var string[] $passwordChars */
        SecureRandom::shuffle($passwordChars);
        return implode('', $passwordChars);
    }

    private static function mapRequirementKey(string $key): ?CharacterSet
    {
        return match ($key) {
            'lower' => CharacterSet::LOWER,
            'upper' => CharacterSet::UPPER,
            'digit' => CharacterSet::DIGIT,
            'symbol' => CharacterSet::SYMBOL_BASIC,
            'symbol_extended' => CharacterSet::SYMBOL_EXTENDED,
            'accented_lower' => CharacterSet::ACCENTED_LOWER,
            'accented_upper' => CharacterSet::ACCENTED_UPPER,
            default => null,
        };
    }
}
