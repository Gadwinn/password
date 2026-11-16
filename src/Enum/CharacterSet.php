<?php

declare(strict_types=1);

namespace G\Password\Enum;

/**
 * Character sets supported by the password generator / validator.
 * Each enum case returns its UTF-8 safe list of characters.
 */
enum CharacterSet: string
{
    case LOWER = 'lower';
    case UPPER = 'upper';
    case DIGIT = 'digit';
    case SYMBOL_BASIC = 'symbol_basic';
    case SYMBOL_EXTENDED = 'symbol_extended';
    case ACCENTED_LOWER = 'accented_lower';
    case ACCENTED_UPPER = 'accented_upper';

    /**
     * Characters that are easily mistaken for one another or awkward to type or read aloud.
     */
    public const string AMBIGUOUS = '0Oo1lI|{}[]()<>`"\'.,;:/\\';

    /**
     * @return string[]
     */
    public static function ambiguousCharacters(): array
    {
        return str_split(self::AMBIGUOUS);
    }

    /**
     * Returns the list of characters for the set as an array of UTF-8 characters.
     * @return string[]
     */
    public function characters(): array
    {
        return match ($this) {
            self::LOWER => self::split('abcdefghijklmnopqrstuvwxyz'),
            self::UPPER => self::split('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            self::DIGIT => self::split('0123456789'),
            self::SYMBOL_BASIC => self::split('!@#$%^&*'),
            // Extended symbols are a curated set excluding whitespace.
            self::SYMBOL_EXTENDED => self::split("()[]{}<>~`_-+=|:;,.?\/\\\"'"),
            self::ACCENTED_LOWER => self::split('àáâäãåæçèéêëìíîïñòóôöõøœùúûüýÿ'),
            self::ACCENTED_UPPER => self::split('ÀÁÂÄÃÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÖÕØŒÙÚÛÜÝ'),
        };
    }

    /**
     * Builds a combined unique character array from provided sets.
     * @param CharacterSet[] $sets
     * @return string[]
     */
    public static function combinedCharacters(array $sets): array
    {
        $pool = [];
        foreach ($sets as $set) {
            foreach ($set->characters() as $ch) {
                $pool[$ch] = true;
            }
        }
        // Digits used as array keys come back as integers
        return array_map(strval(...), array_keys($pool));
    }

    /**
     * @param string $input
     * @return string[]
     */
    private static function split(string $input): array
    {
        // Split UTF-8 safe into individual code points (basic BMP usage).
        return preg_split('//u', $input, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }
}
