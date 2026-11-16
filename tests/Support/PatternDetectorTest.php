<?php

declare(strict_types=1);

namespace G\Password\Tests\Support;

use G\Password\Support\PatternDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PatternDetectorTest extends TestCase
{
    #[DataProvider('sequenceProvider')]
    public function testHasSequence(string $password, bool $expected): void
    {
        $this->assertSame($expected, PatternDetector::hasSequence($password));
    }

    /** @return array<string, array{string, bool}> */
    public static function sequenceProvider(): array
    {
        return [
            'empty' => ['', false],
            'increasing letters' => ['xxabcdxx', true],
            'increasing digits' => ['a1234b', true],
            'decreasing digits' => ['a4321b', true],
            'decreasing letters' => ['zdcbaz', true],
            'too short' => ['abc', false],
            'up then down' => ['abcba', false],
            'broken run' => ['abxcd', false],
            'random' => ['K7#xYj!2', false],
            'accented letters are not a byte sequence' => ['éèàùéèàù', false],
            'accented code point sequence' => ['àáâã', true],
        ];
    }

    public function testSequenceMinimumRunIsConfigurable(): void
    {
        $this->assertTrue(PatternDetector::hasSequence('abc', 3));
        $this->assertFalse(PatternDetector::hasSequence('abcd', 5));
    }

    #[DataProvider('repeatProvider')]
    public function testHasRepeatingRun(string $password, bool $expected): void
    {
        $this->assertSame($expected, PatternDetector::hasRepeatingRun($password));
    }

    /** @return array<string, array{string, bool}> */
    public static function repeatProvider(): array
    {
        return [
            'empty' => ['', false],
            'four identical' => ['xaaaax', true],
            'three identical' => ['xaaax', false],
            'multi-byte run' => ['éééé', true],
            'separated' => ['aabaa', false],
        ];
    }

    public function testRepeatMinimumRunIsConfigurable(): void
    {
        $this->assertTrue(PatternDetector::hasRepeatingRun('aa', 2));
    }
}
