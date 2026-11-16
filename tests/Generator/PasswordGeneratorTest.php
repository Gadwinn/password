<?php

declare(strict_types=1);

namespace G\Password\Tests\Generator;

use G\Password\Generator\PasswordGenerator;
use PHPUnit\Framework\TestCase;

final class PasswordGeneratorTest extends TestCase
{
    public function testGeneratesRequiredLength(): void
    {
        $gen = new PasswordGenerator();
        $pwd = $gen->generate([
            'length' => 16,
            'requirements' => [ 'lower' => 4, 'upper' => 2, 'digit' => 2, 'symbol' => 2 ],
            'exclude_ambiguous' => true,
        ]);
        $this->assertSame(16, mb_strlen($pwd));
    }

    public function testRespectsMinimums(): void
    {
        $gen = new PasswordGenerator();
        $pwd = $gen->generate([
            'length' => 20,
            'requirements' => [ 'lower' => 5, 'digit' => 5 ],
        ]);
        $lower = preg_match_all('/[a-z]/u', $pwd);
        $digits = preg_match_all('/[0-9]/u', $pwd);
        $this->assertGreaterThanOrEqual(5, $lower);
        $this->assertGreaterThanOrEqual(5, $digits);
    }

    public function testExcludesAmbiguousAndCustomCharacters(): void
    {
        $gen = new PasswordGenerator();

        for ($i = 0; $i < 20; $i++) {
            $pwd = $gen->generate([
                'length' => 64,
                'requirements' => ['lower' => 1, 'upper' => 1, 'digit' => 1, 'symbol_extended' => 1],
                'exclude_ambiguous' => true,
                'exclude' => 'abcXYZ9',
            ]);

            $this->assertFalse(strpbrk($pwd, \G\Password\Enum\CharacterSet::AMBIGUOUS . 'abcXYZ9'), $pwd);
        }
    }

    public function testOnlyActiveSetsAreUsed(): void
    {
        $pwd = (new PasswordGenerator())->generate(['length' => 200, 'requirements' => ['digit' => 1]]);

        $this->assertMatchesRegularExpression('/^\d{200}$/', $pwd);
    }

    public function testAccentedCharactersCountAsOneCharacter(): void
    {
        $pwd = (new PasswordGenerator())->generate(['length' => 12, 'requirements' => ['accented_lower' => 12]]);

        $this->assertSame(12, mb_strlen($pwd, 'UTF-8'));
        $this->assertDoesNotMatchRegularExpression('/[\x00-\x7F]/', $pwd);
    }

    public function testGeneratedPasswordsDiffer(): void
    {
        $gen = new PasswordGenerator();
        $config = ['length' => 32, 'requirements' => ['lower' => 1, 'upper' => 1, 'digit' => 1]];

        $this->assertNotSame($gen->generate($config), $gen->generate($config));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidConfigProvider')]
    public function testInvalidConfigurationIsRejected(array $config): void
    {
        $this->expectException(\G\Password\Exception\GenerationException::class);

        (new PasswordGenerator())->generate($config);
    }

    /** @return array<string, array{array<string,mixed>}> */
    public static function invalidConfigProvider(): array
    {
        return [
            'empty config' => [[]],
            'missing length' => [['requirements' => ['lower' => 1]]],
            'missing requirements' => [['length' => 8]],
            'zero length' => [['length' => 0, 'requirements' => ['lower' => 1]]],
            'no active set' => [['length' => 8, 'requirements' => ['lower' => 0]]],
            'negative minimum' => [['length' => 8, 'requirements' => ['lower' => -1]]],
            'unknown set' => [['length' => 8, 'requirements' => ['emoji' => 1]]],
            'minimums above length' => [['length' => 3, 'requirements' => ['lower' => 2, 'upper' => 2]]],
            'set emptied by exclusions' => [['length' => 8, 'requirements' => ['digit' => 1], 'exclude' => '0123456789']],
        ];
    }
}
