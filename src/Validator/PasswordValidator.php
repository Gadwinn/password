<?php

declare(strict_types=1);

namespace G\Password\Validator;

use G\Password\Enum\CharacterSet;
use G\Password\Enum\IssueType;
use G\Password\Enum\ScoreLevel;
use G\Password\Exception\ValidationException;
use G\Password\Model\ValidationIssue;
use G\Password\Model\ValidationResult;
use G\Password\Model\ValidationRules;
use G\Password\Support\Entropy;
use G\Password\Support\PatternDetector;

/**
 * Validates passwords against a set of rules producing a rich result object.
 */
final class PasswordValidator
{
    private const float ENTROPY_FAIR = 40.0;
    private const float ENTROPY_GOOD = 60.0;
    private const float ENTROPY_STRONG = 80.0;

    /**
     * Validate a password with the provided rules array.
     *
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
    public function validate(string $password, array $rules): ValidationResult
    {
        $r = ValidationRules::fromArray($rules);
        $length = self::utf8Length($password);

        $issues = [];

        if ($length < $r->minLength()) {
            $issues[] = new ValidationIssue(
                IssueType::LENGTH,
                'Password shorter than minimum length.',
                ['min' => $r->minLength(), 'length' => $length]
            );
        }
        if ($r->maxLength() !== 0 && $length > $r->maxLength()) {
            $issues[] = new ValidationIssue(
                IssueType::LENGTH,
                'Password longer than maximum length.',
                ['max' => $r->maxLength(), 'length' => $length]
            );
        }

        // Build counts by character set.
        $counts = [
            'lower' => 0,
            'upper' => 0,
            'digit' => 0,
            'symbol' => 0,
            'symbol_extended' => 0,
            'accented_lower' => 0,
            'accented_upper' => 0,
        ];
        $chars = preg_split('//u', $password, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        foreach ($chars as $ch) {
            $counts['lower'] += self::inSet($ch, CharacterSet::LOWER);
            $counts['upper'] += self::inSet($ch, CharacterSet::UPPER);
            $counts['digit'] += self::inSet($ch, CharacterSet::DIGIT);
            $counts['symbol'] += self::inSet($ch, CharacterSet::SYMBOL_BASIC);
            $counts['symbol_extended'] += self::inSet($ch, CharacterSet::SYMBOL_EXTENDED);
            $counts['accented_lower'] += self::inSet($ch, CharacterSet::ACCENTED_LOWER);
            $counts['accented_upper'] += self::inSet($ch, CharacterSet::ACCENTED_UPPER);
        }

        // Required sets.
        foreach ($r->requirements() as $key => $min) {
            $min = (int)$min;
            if ($min <= 0) {
                continue;
            }
            if (!array_key_exists($key, $counts)) {
                throw new ValidationException('Unknown requirement key: ' . $key);
            }
            if ($counts[$key] < $min) {
                $issues[] = new ValidationIssue(
                    IssueType::REQUIRED_SET_MISSING,
                    'Requirement not met for ' . $key,
                    ['required' => $min, 'found' => $counts[$key]]
                );
            }
        }

        // Ambiguous characters.
        if ($r->excludeAmbiguous()) {
            $ambiguousFound = array_intersect($chars, CharacterSet::ambiguousCharacters());
            if (!empty($ambiguousFound)) {
                $issues[] = new ValidationIssue(
                    IssueType::AMBIGUOUS_PRESENT,
                    'Ambiguous characters present.',
                    ['characters' => array_values(array_unique($ambiguousFound))]
                );
            }
        }

        // Blacklist.
        if (in_array($password, $r->blacklist(), true)) {
            $issues[] = new ValidationIssue(IssueType::BLACKLIST, 'Password is blacklisted.');
        }

        // Excluded characters.
        if ($r->excludedCharacters()) {
            $excludedPresent = array_intersect($chars, $r->excludedCharacters());
            if (!empty($excludedPresent)) {
                $issues[] = new ValidationIssue(
                    IssueType::BLACKLIST,
                    'Password contains excluded characters.',
                    ['characters' => array_values(array_unique($excludedPresent))]
                );
            }
        }

        // Patterns.
        $hasRepeat = PatternDetector::hasRepeatingRun($password);
        $hasSequence = PatternDetector::hasSequence($password);

        if ($hasRepeat) {
            $issues[] = new ValidationIssue(IssueType::REPEAT_PATTERN, 'Repeating character run detected.');
        }
        if ($hasSequence) {
            $issues[] = new ValidationIssue(IssueType::SEQUENCE_PATTERN, 'Sequential pattern detected.');
        }

        // Entropy & scoring.
        $alphabetSize = self::estimateAlphabetSize($counts);

        // Theoretical entropy (if password was random from alphabet)
        $entropyTheoretical = Entropy::bits($length, $alphabetSize);

        // Estimated real entropy (Shannon + pattern penalties)
        $entropyEstimated = Entropy::estimatedEntropy($password, $alphabetSize, $hasRepeat, $hasSequence);

        // Use estimated entropy for scoring and validation
        $score = self::scoreFromEntropy($entropyEstimated, $issues);
        if ($entropyEstimated < self::ENTROPY_FAIR) {
            $issues[] = new ValidationIssue(
                IssueType::ENTROPY_LOW,
                'Entropy below recommended threshold.',
                ['bits' => $entropyEstimated, 'theoretical' => $entropyTheoretical]
            );
        }
        $crackSeconds = self::estimateCrackTime($entropyEstimated, $r->attemptsPerSecond());

        $valid = empty(array_filter($issues, fn(ValidationIssue $i) => $i->type !== IssueType::ENTROPY_LOW));
        $final = new ValidationResult($valid, $score, $entropyEstimated, $entropyTheoretical, $crackSeconds, $length);
        $final->setCounts($counts);
        foreach ($issues as $issue) {
            $final->addIssue($issue);
        }
        return $final;
    }

    private static function utf8Length(string $input): int
    {
        return count(preg_split('//u', $input, -1, PREG_SPLIT_NO_EMPTY) ?: []);
    }

    private static function inSet(string $char, CharacterSet $set): int
    {
        return in_array($char, $set->characters(), true) ? 1 : 0;
    }

    /**
     * Estimate alphabet size from counts (union of sets used).
     * @param array<string,int> $counts
     */
    private static function estimateAlphabetSize(array $counts): int
    {
        $size = 0;
        $map = [
            'lower' => CharacterSet::LOWER,
            'upper' => CharacterSet::UPPER,
            'digit' => CharacterSet::DIGIT,
            'symbol' => CharacterSet::SYMBOL_BASIC,
            'symbol_extended' => CharacterSet::SYMBOL_EXTENDED,
            'accented_lower' => CharacterSet::ACCENTED_LOWER,
            'accented_upper' => CharacterSet::ACCENTED_UPPER,
        ];
        foreach ($counts as $key => $c) {
            if ($c > 0 && isset($map[$key])) {
                $size += count($map[$key]->characters());
            }
        }
        return max($size, 1);
    }

    /**
     * Crack time estimation using entropy: assume attempts per second => 2^(bits-1)/attemptsPerSecond average.
     */
    private static function estimateCrackTime(float $entropyBits, float $attemptsPerSecond): float
    {
        if ($entropyBits <= 0.0 || $attemptsPerSecond <= 0.0) {
            return 0.0;
        }
        // Half of the 2^bits possibilities are tried on average.
        return exp(($entropyBits - 1) * M_LN2) / $attemptsPerSecond;
    }

    /**
     * Score mapping based on entropy and presence of severe issues
     * (excluding low entropy itself which is informational).
     * @param ValidationIssue[] $issues
     */
    private static function scoreFromEntropy(float $bits, array $issues): ScoreLevel
    {
        $severe = array_filter($issues, fn(ValidationIssue $i) => $i->type !== IssueType::ENTROPY_LOW);
        if (!empty($severe)) {
            return ScoreLevel::NONE;
        }
        if ($bits < self::ENTROPY_FAIR) {
            return ScoreLevel::WEAK;
        }
        if ($bits < self::ENTROPY_GOOD) {
            return ScoreLevel::FAIR;
        }
        if ($bits < self::ENTROPY_STRONG) {
            return ScoreLevel::GOOD;
        }
        return ScoreLevel::STRONG;
    }
}
