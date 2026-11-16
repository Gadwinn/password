<?php

declare(strict_types=1);

namespace G\Password\Support;

/**
 * Simple pattern detection for sequences and repeats.
 */
final class PatternDetector
{
    /**
     * Detects if password contains a straight sequence of length >= $minRun,
     * increasing ("abcd", "1234") or decreasing ("dcba", "4321").
     */
    public static function hasSequence(string $password, int $minRun = 4): bool
    {
        $chars = preg_split('//u', $password, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $run = 1;
        $direction = 0;
        for ($i = 1; $i < count($chars); $i++) {
            // Code points, not bytes: accented letters are multi-byte.
            $step = mb_ord($chars[$i], 'UTF-8') - mb_ord($chars[$i - 1], 'UTF-8');
            if (abs($step) !== 1) {
                $run = 1;
                $direction = 0;
                continue;
            }
            $run = $step === $direction ? $run + 1 : 2;
            $direction = $step;
            if ($run >= $minRun) {
                return true;
            }
        }
        return false;
    }

    /**
     * Detects a repeated single character run of length >= $minRepeat.
     */
    public static function hasRepeatingRun(string $password, int $minRepeat = 4): bool
    {
        if ($password === '') {
            return false;
        }
        $chars = preg_split('//u', $password, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $run = 1;
        for ($i = 1; $i < count($chars); $i++) {
            if ($chars[$i] === $chars[$i - 1]) {
                $run++;
                if ($run >= $minRepeat) {
                    return true;
                }
            } else {
                $run = 1;
            }
        }
        return false;
    }
}
