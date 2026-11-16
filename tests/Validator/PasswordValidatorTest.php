<?php

declare(strict_types=1);

namespace G\Password\Tests\Validator;

use G\Password\Validator\PasswordValidator;
use G\Password\Enum\ScoreLevel;
use PHPUnit\Framework\TestCase;

final class PasswordValidatorTest extends TestCase
{
    public function testValidationPassesForStrongPassword(): void
    {
        $validator = new PasswordValidator();
        $password = 'Ab9!xY7#LmQ2@';
        $result = $validator->validate($password, [
            'min_length' => 12,
            'requirements' => [ 'lower' => 2, 'upper' => 2, 'digit' => 2, 'symbol' => 2 ],
            'exclude_ambiguous' => true,
        ]);
        $this->assertTrue($result->isValid());
        // With Shannon entropy, score may vary based on character distribution
        $this->assertContains($result->score(), [ScoreLevel::FAIR, ScoreLevel::GOOD, ScoreLevel::STRONG]);
    }

    public function testValidationFailsForShortPassword(): void
    {
        $validator = new PasswordValidator();
        $password = 'Ab1!';
        $result = $validator->validate($password, [
            'min_length' => 8,
            'requirements' => [ 'lower' => 1, 'upper' => 1, 'digit' => 1, 'symbol' => 1 ],
        ]);
        $this->assertFalse($result->isValid());
        $this->assertEquals(ScoreLevel::NONE, $result->score());
    }

    public function testEntropyCalculationReflectsRealDistribution(): void
    {
        $validator = new PasswordValidator();
        
        // Weak password with repetition: "aaaaaaaa"
        $weakResult = $validator->validate('aaaaaaaa', ['min_length' => 8]);
        
        // Strong random-like password: "Kj#9xL2@"
        $strongResult = $validator->validate('Kj#9xL2@', ['min_length' => 8]);
        
        // Estimated entropy should be much lower for repetitive password
        $this->assertLessThan($strongResult->entropyBits(), $weakResult->entropyBits());
        $this->assertEquals(ScoreLevel::NONE, $weakResult->score());
    }

    public function testTheoreticalVsEstimatedEntropy(): void
    {
        $validator = new PasswordValidator();
        
        // Password with patterns should have lower estimated than theoretical
        $result = $validator->validate('abcdefgh', ['min_length' => 8]);
        
        $this->assertGreaterThan(0, $result->entropyBitsTheoretical());
        $this->assertGreaterThan(0, $result->entropyBits());
        
        // Theoretical assumes random generation, should be higher
        // (unless password happens to be perfectly uniform and random)
        $this->assertGreaterThanOrEqual($result->entropyBits(), $result->entropyBitsTheoretical());
    }

    public function testCountsPerCharacterSet(): void
    {
        $result = (new PasswordValidator())->validate('aB3!(éÉ', ['min_length' => 1]);

        $this->assertSame(
            ['lower' => 1, 'upper' => 1, 'digit' => 1, 'symbol' => 1, 'symbol_extended' => 1, 'accented_lower' => 1, 'accented_upper' => 1],
            $result->counts()
        );
        $this->assertSame(7, $result->length());
    }

    /**
     * @param array<string,mixed> $rules
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('issueProvider')]
    public function testIssueIsReported(string $password, array $rules, \G\Password\Enum\IssueType $expected): void
    {
        $result = (new PasswordValidator())->validate($password, $rules);
        $types = array_map(static fn($issue) => $issue->type, $result->issues());

        $this->assertContains($expected, $types);
        $this->assertFalse($result->isValid());
        $this->assertSame(\G\Password\Enum\ScoreLevel::NONE, $result->score());
    }

    /** @return array<string, array{string, array<string,mixed>, \G\Password\Enum\IssueType}> */
    public static function issueProvider(): array
    {
        $type = \G\Password\Enum\IssueType::class;

        return [
            'too long' => ['Kx7#Yj!2Qm', ['max_length' => 9], constant($type . '::LENGTH')],
            'missing set' => ['kx7#yj!2qm', ['requirements' => ['upper' => 1]], constant($type . '::REQUIRED_SET_MISSING')],
            'ambiguous' => ['Kx7#Yj!2Ql', ['exclude_ambiguous' => true], constant($type . '::AMBIGUOUS_PRESENT')],
            'blacklist' => ['Kx7#Yj!2Qm', ['blacklist' => ['Kx7#Yj!2Qm']], constant($type . '::BLACKLIST')],
            'excluded character' => ['Kx7#Yj!2Qm', ['exclude' => '#'], constant($type . '::BLACKLIST')],
            'repeat' => ['Kx7#aaaaYj!2', [], constant($type . '::REPEAT_PATTERN')],
            'sequence' => ['Kx7#abcdYj!2', [], constant($type . '::SEQUENCE_PATTERN')],
            'decreasing sequence' => ['Kx7#9876Yj!', [], constant($type . '::SEQUENCE_PATTERN')],
        ];
    }

    public function testLowEntropyAloneDoesNotInvalidate(): void
    {
        $result = (new PasswordValidator())->validate('Kx7#Yj!2', []);
        $types = array_map(static fn($issue) => $issue->type, $result->issues());

        $this->assertSame([\G\Password\Enum\IssueType::ENTROPY_LOW], $types);
        $this->assertTrue($result->isValid());
        $this->assertSame(\G\Password\Enum\ScoreLevel::WEAK, $result->score());
    }

    public function testCrackTimeFollowsEntropyAndSpeed(): void
    {
        $validator = new PasswordValidator();
        $slow = $validator->validate('Kx7#Yj!2Qm', ['attempts_per_second' => 1.0]);
        $fast = $validator->validate('Kx7#Yj!2Qm', ['attempts_per_second' => 1000.0]);

        $this->assertEqualsWithDelta(2 ** ($slow->entropyBits() - 1), $slow->crackTimeSeconds(), $slow->crackTimeSeconds() * 1e-9);
        $this->assertEqualsWithDelta($slow->crackTimeSeconds() / 1000, $fast->crackTimeSeconds(), $fast->crackTimeSeconds() * 1e-9);
    }

    /**
     * @param array<string,mixed> $rules
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('invalidRulesProvider')]
    public function testInvalidRulesAreRejected(array $rules): void
    {
        $this->expectException(\G\Password\Exception\ValidationException::class);

        (new PasswordValidator())->validate('Kx7#Yj!2Qm', $rules);
    }

    /** @return array<string, array{array<string,mixed>}> */
    public static function invalidRulesProvider(): array
    {
        return [
            'zero min length' => [['min_length' => 0]],
            'max below min' => [['min_length' => 8, 'max_length' => 4]],
            'negative requirement' => [['requirements' => ['lower' => -1]]],
            'unknown requirement' => [['requirements' => ['emoji' => 1]]],
        ];
    }
}
