# Password
PHP 8.3+ library to generate and validate passwords with configurable policies. Cryptographically secure randomness, UTF-8 support (accented letters), rich validation metrics, and no runtime dependencies.

## Features
- Configurable generator: length, per-set minimums, exclude ambiguous characters, custom exclusions
- Character sets: lower/upper case, digits, basic/extended symbols, accented letters
- Cryptographically secure randomness via `random_int()` and Fisher–Yates shuffle
- Validator with detailed result: counts per class, entropy bits, crack-time estimate, issues list, strength score
- No runtime dependencies, PSR-4/PSR-12 compliant, PHP 8.3+ (`ext-mbstring`)

## Install

```
composer require gadwinn/password
```

## Usage

### Generator

```php
use G\Password\Generator\PasswordGenerator;

$generator = new PasswordGenerator();
$password = $generator->generate([
	'length' => 16,
	'requirements' => [
		'lower' => 2,
		'upper' => 2,
		'digit' => 2,
		'symbol' => 2,
		// optional
		'symbol_extended' => 0,
		'accented_lower' => 0,
		'accented_upper' => 0,
	],
	'exclude_ambiguous' => true,
	'exclude' => '{}[]',
]);
```

### Validator

```php
use G\Password\Validator\PasswordValidator;

$validator = new PasswordValidator();
$result = $validator->validate($password, [
	'min_length' => 12,
	'requirements' => [
		'lower' => 2,
		'upper' => 2,
		'digit' => 2,
		'symbol' => 2,
	],
	'exclude_ambiguous' => true,
	'attempts_per_second' => 1_000_000_000.0,
]);

if ($result->isValid()) {
	// OK to accept
}

$result->score();            // ScoreLevel enum
$result->entropyBits();      // float (estimated real entropy)
$result->entropyBitsTheoretical(); // float (if password was random)
$result->crackTimeSeconds(); // float
$result->length();           // int
$result->counts();           // array<string,int>
$result->issues();           // ValidationIssue[]
```

## Configuration Reference

Generator (`PasswordGenerator::generate(array $config): string`):
- `length` (int, required): total length
- `requirements` (array<string,int>): per-set minimums; keys: `lower`, `upper`, `digit`, `symbol`, `symbol_extended`, `accented_lower`, `accented_upper`
- `exclude_ambiguous` (bool): exclude ambiguous chars like `0/O/o`, `1/l/I`, etc.
- `exclude` (string): additional characters to exclude

Validator (`PasswordValidator::validate(string $password, array $rules): ValidationResult`):
- `min_length` (int, default 8)
- `max_length` (int, default 0 = unlimited)
- `requirements` (array<string,int>) same keys as generator
- `exclude_ambiguous` (bool)
- `blacklist` (string[])
- `exclude` (string) characters not allowed
- `attempts_per_second` (float, default 1e9)

## Strength Scoring

### Entropy Calculation
The library provides **two entropy measurements**:

1. **Theoretical Entropy** (`entropyBitsTheoretical()`): Assumes the password was generated randomly from the detected character sets. Calculated as `length * log2(alphabetSize)`.

2. **Estimated Real Entropy** (`entropyBits()`): Uses **Shannon entropy** based on actual character frequency distribution, with penalties for detected patterns:
   - Shannon formula: `-sum(p_i * log2(p_i)) * length`
   - Repetition pattern penalty: -25%
   - Sequential pattern penalty: -30% (4 consecutive characters or more, increasing `abcd` or decreasing `4321`)
   - Maximum combined penalty: -50%

Example: `"aaaaaaaa"` has 0 bits of real entropy (completely predictable), while `"K7#xYj!2"` with uniform distribution has much higher entropy.

### Score Levels
Based on **estimated entropy**:
- `NONE`: a rule is violated (length, required set, excluded or ambiguous character, blacklist, repetition, sequence); `isValid()` is then `false`. Low entropy alone is reported as an issue but does not invalidate the password.
- `WEAK`: < 40 bits
- `FAIR`: 40-59 bits
- `GOOD`: 60-79 bits
- `STRONG`: ≥ 80 bits

## Security Notes
- Uses `random_int()` everywhere; no `mt_rand` or `rand`
- Secure Fisher–Yates shuffle
- Rejects impossible configurations (sum of minimums > length, empty pools)
- UTF-8 splitting with `preg_split('//u', ...)`

## Development

Commands:

```
composer install
composer test-all
composer test-unit-coverage
composer test-stan
composer test-cs
```

## License

MIT
