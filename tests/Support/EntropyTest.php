<?php

declare(strict_types=1);

namespace G\Password\Tests\Support;

use G\Password\Support\Entropy;
use PHPUnit\Framework\TestCase;

final class EntropyTest extends TestCase
{
    public function testTheoreticalEntropyForUniformDistribution(): void
    {
        // 8 chars from 26-letter alphabet: 8 * log2(26) ≈ 37.6
        $entropy = Entropy::bits(8, 26);
        $this->assertEqualsWithDelta(37.6, $entropy, 0.1);
    }

    public function testShannonEntropyForUniformPassword(): void
    {
        // "abcdefgh" - 8 unique chars, uniform distribution
        // Per-char entropy: -8 * (1/8 * log2(1/8)) = 3 bits
        // Total: 3 * 8 = 24 bits
        $entropy = Entropy::shannonEntropy('abcdefgh');
        $this->assertEqualsWithDelta(24.0, $entropy, 0.1);
    }

    public function testShannonEntropyForRepeatingPassword(): void
    {
        // "aaaaaaaa" - all same char
        // Per-char entropy: -(1 * log2(1)) = 0
        // Total: 0 bits (no information, completely predictable)
        $entropy = Entropy::shannonEntropy('aaaaaaaa');
        $this->assertEquals(0.0, $entropy);
    }

    public function testShannonEntropyForPartialRepeat(): void
    {
        // "aaabbbcc" - 3a, 3b, 2c
        // Frequencies: 3/8, 3/8, 2/8
        $entropy = Entropy::shannonEntropy('aaabbbcc');
        
        // Should be less than uniform (24 bits) but more than zero
        $this->assertGreaterThan(0.0, $entropy);
        $this->assertLessThan(24.0, $entropy);
    }

    public function testEstimatedEntropyAppliesPenalties(): void
    {
        $password = 'abcdefgh';
        $shannon = Entropy::shannonEntropy($password);
        
        // With repeat pattern penalty
        $withRepeat = Entropy::estimatedEntropy($password, 26, true, false);
        $this->assertLessThan($shannon, $withRepeat);
        $this->assertEqualsWithDelta($shannon * 0.75, $withRepeat, 0.1);
        
        // With sequence pattern penalty
        $withSequence = Entropy::estimatedEntropy($password, 26, false, true);
        $this->assertLessThan($shannon, $withSequence);
        $this->assertEqualsWithDelta($shannon * 0.70, $withSequence, 0.1);
        
        // With both penalties (capped at 50%)
        $withBoth = Entropy::estimatedEntropy($password, 26, true, true);
        $this->assertEqualsWithDelta($shannon * 0.50, $withBoth, 0.1);
    }

    public function testEstimatedEntropyNeverNegative(): void
    {
        $password = 'a';
        $entropy = Entropy::estimatedEntropy($password, 26, true, true);
        $this->assertGreaterThanOrEqual(0.0, $entropy);
    }
}
