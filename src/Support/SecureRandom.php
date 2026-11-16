<?php

declare(strict_types=1);

namespace G\Password\Support;

/**
 * Secure randomness helpers using random_int only.
 */
final class SecureRandom
{
    /**
     * Returns a random integer in [0, $maxExclusive - 1].
     */
    public static function int(int $maxExclusive): int
    {
        if ($maxExclusive < 1) {
            throw new \InvalidArgumentException('maxExclusive must be >= 1');
        }
        return random_int(0, $maxExclusive - 1);
    }

    /**
     * Performs a Fisher-Yates shuffle in-place on array of strings.
     * @param string[] $array
     */
    public static function shuffle(array &$array): void
    {
        for ($i = count($array) - 1; $i > 0; $i--) {
            $j = self::int($i + 1);
            [$array[$i], $array[$j]] = [$array[$j], $array[$i]];
        }
    }
}
