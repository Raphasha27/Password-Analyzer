import math
import string
from dataclasses import dataclass, field


COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "letmein", "dragon", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "welcome", "shadow", "ashley", "football", "jesus",
    "michael", "ninja", "mustang", "password1", "admin", "administrator",
}


@dataclass
class PasswordAnalysis:
    password_length: int
    entropy: float
    char_sets: list[str]
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    is_common: bool
    nist_score: int
    crack_time_estimate: str
    strength: str
    suggestions: list[str] = field(default_factory=list)


class PasswordAnalyzer:
    def analyze(self, password: str) -> PasswordAnalysis:
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        char_sets = []
        pool_size = 0
        if has_lower:
            char_sets.append("lowercase")
            pool_size += 26
        if has_upper:
            char_sets.append("uppercase")
            pool_size += 26
        if has_digits:
            char_sets.append("digits")
            pool_size += 10
        if has_special:
            char_sets.append("special")
            pool_size += 32

        if pool_size == 0:
            pool_size = 1

        entropy = length * math.log2(pool_size) if length > 0 else 0.0
        is_common = password.lower() in COMMON_PASSWORDS

        nist_score = self._nist_score(password, length)
        crack_time = self._estimate_crack_time(entropy, is_common)
        strength = self._classify_strength(entropy, is_common, length)
        suggestions = self._get_suggestions(password, length, has_upper, has_lower,
                                             has_digits, has_special, is_common)

        return PasswordAnalysis(
            password_length=length,
            entropy=round(entropy, 2),
            char_sets=char_sets,
            has_uppercase=has_upper,
            has_lowercase=has_lower,
            has_digits=has_digits,
            has_special=has_special,
            is_common=is_common,
            nist_score=nist_score,
            crack_time_estimate=crack_time,
            strength=strength,
            suggestions=suggestions,
        )

    @staticmethod
    def _nist_score(password: str, length: int) -> int:
        score = 0
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        if any(c.isupper() for c in password) and any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        return min(score, 5)

    @staticmethod
    def _estimate_crack_time(entropy: float, is_common: bool) -> str:
        if is_common:
            return "instantly (common password)"
        if entropy < 28:
            return "seconds"
        if entropy < 36:
            return "minutes"
        if entropy < 60:
            return "hours to days"
        if entropy < 80:
            return "months to years"
        return "centuries"

    @staticmethod
    def _classify_strength(entropy: float, is_common: bool, length: int) -> str:
        if is_common or length < 8:
            return "very_weak"
        if entropy < 36:
            return "weak"
        if entropy < 60:
            return "moderate"
        if entropy < 80:
            return "strong"
        return "very_strong"

    @staticmethod
    def _get_suggestions(password: str, length: int, has_upper: bool, has_lower: bool,
                          has_digits: bool, has_special: bool, is_common: bool) -> list[str]:
        suggestions = []
        if is_common:
            suggestions.append("This password is commonly used and easily guessed")
        if length < 8:
            suggestions.append("Use at least 8 characters")
        if length < 12:
            suggestions.append("Consider using 12+ characters for better security")
        if not has_upper:
            suggestions.append("Add uppercase letters")
        if not has_lower:
            suggestions.append("Add lowercase letters")
        if not has_digits:
            suggestions.append("Add digits")
        if not has_special:
            suggestions.append("Add special characters")
        if not is_common and length == len(set(password.lower())):
            suggestions.append("Consider repeating characters less predictable")
        return suggestions

    def batch_analyze(self, passwords: list[str]) -> list[PasswordAnalysis]:
        return [self.analyze(p) for p in passwords]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Password Analyzer")
    parser.add_argument("--password", help="Password to analyze")
    parser.add_argument("--file", help="File containing passwords (one per line)")
    args = parser.parse_args()

    analyzer = PasswordAnalyzer()
    passwords = []
    if args.password:
        passwords = [args.password]
    elif args.file:
        with open(args.file) as f:
            passwords = [line.strip() for line in f if line.strip()]

    for pw in passwords:
        a = analyzer.analyze(pw)
        print(f"\nPassword: {'*' * len(pw)} (len={a.password_length})")
        print(f"  Strength: {a.strength}")
        print(f"  Entropy: {a.entropy} bits")
        print(f"  NIST Score: {a.nist_score}/5")
        print(f"  Character sets: {', '.join(a.char_sets)}")
        print(f"  Common password: {a.is_common}")
        print(f"  Crack time: {a.crack_time_estimate}")
        for s in a.suggestions:
            print(f"  - {s}")


if __name__ == "__main__":
    main()
