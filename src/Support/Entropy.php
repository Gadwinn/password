<?php

declare(strict_types=1);

namespace G\Password\Support;

/**
 * Entropy estimation helpers.
 */
final class Entropy
{
    private const float REPEAT_PENALTY = 0.25;
    private const float SEQUENCE_PENALTY = 0.30;
    private const float MAX_PENALTY = 0.50;

    /**
     * Calculates naive entropy bits: length * log2(alphabetSize).
     * This assumes uniform random distribution from the alphabet.
     */
    public static function bits(int $length, int $alphabetSize): float
    {
        if ($length <= 0 || $alphabetSize <= 1) {
            return 0.0;
        }
        return $length * log($alphabetSize, 2.0);
    }

    /**
     * Calculates Shannon entropy based on actual character frequencies.
     * This reflects the real information content of the password.
     * H = -sum(p_i * log2(p_i)) where p_i is the frequency of character i.
     *
     * @param string $password The password to analyze
     * @return float Shannon entropy in bits
     */
    public static function shannonEntropy(string $password): float
    {
        if ($password === '') {
            return 0.0;
        }

        $chars = preg_split('//u', $password, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $length = count($chars);

        if ($length === 0) {
            return 0.0;
        }

        // Count frequency of each character
        $frequencies = [];
        foreach ($chars as $char) {
            if (!isset($frequencies[$char])) {
                $frequencies[$char] = 0;
            }
            $frequencies[$char]++;
        }

        // Calculate Shannon entropy
        $entropy = 0.0;
        foreach ($frequencies as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2.0);
        }

        // Total entropy is per-character entropy * length
        return $entropy * $length;
    }

    /**
     * Calculates estimated real-world entropy considering patterns and structure.
     * Applies penalties for detected weaknesses.
     *
     * @param string $password The password to analyze
     * @param int $alphabetSize Theoretical alphabet size
     * @param bool $hasRepeat Whether repeating patterns detected
     * @param bool $hasSequence Whether sequential patterns detected
     * @return float Estimated entropy in bits
     */
    public static function estimatedEntropy(
        string $password,
        int $alphabetSize,
        bool $hasRepeat,
        bool $hasSequence
    ): float {
        // Start with Shannon entropy (real distribution)
        $shannon = self::shannonEntropy($password);

        // Apply penalties for structural weaknesses
        $penalty = 0.0;

        if ($hasRepeat) {
            // Repeating patterns reduce entropy significantly
            $penalty += $shannon * self::REPEAT_PENALTY;
        }

        if ($hasSequence) {
            // Sequential patterns are highly predictable
            $penalty += $shannon * self::SEQUENCE_PENALTY;
        }

        // Don't let penalties exceed 50% of Shannon entropy
        $penalty = min($penalty, $shannon * self::MAX_PENALTY);

        return max(0.0, $shannon - $penalty);
    }
}
