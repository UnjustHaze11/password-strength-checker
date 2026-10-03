#!/usr/bin/env python3
"""
Password Strength Checker
NIST SP 800-63B Compliant Internal Audit Tool

Evaluates password strength based on length, character variety, and blacklist checks.
Provides actionable feedback for remediation.
"""

import re
from typing import Dict, List, Tuple


class PasswordChecker:
    """Evaluates password strength and provides remediation feedback."""

    def __init__(self, darklist_path: str = "wordlist.txt"):
        """
        Initialize the checker with a darklist.

        Args:
            darklist_path: Path to a file containing blacklisted passwords and common words.
        """
        self.darklist = self._load_darklist(darklist_path)
        self.stats = {
            "total": 0,
            "very_strong": 0,
            "strong": 0,
            "good": 0,
            "fair": 0,
            "weak": 0,
        }

    def _load_darklist(self, path: str) -> set:
        """
        Load blacklisted passwords and common words from file.

        Args:
            path: Path to wordlist file.

        Returns:
            Set of lowercase blacklisted words and passwords.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                return set(word.strip().lower() for word in f if word.strip())
        except FileNotFoundError:
            print(f"Warning: {path} not found. Proceeding without darklist.")
            return set()

    def _score_length(self, password: str) -> Tuple[int, str]:
        """
        Score password based on length (NIST favors length).

        Args:
            password: Password to evaluate.

        Returns:
            Tuple of (score, feedback).
        """
        length = len(password)

        if length < 8:
            return 0, "Password is too short. Add at least 8 characters."
        elif length < 12:
            return 1, "Password could be longer. Aim for 12+ characters."
        elif length < 16:
            return 2, "Length is acceptable (12-15 characters)."
        else:
            return 3, "Excellent length (16+ characters)."

    def _has_variety(self, password: str) -> Tuple[int, List[str]]:
        """
        Check for character variety and return score + feedback.

        Args:
            password: Password to evaluate.

        Returns:
            Tuple of (score, list of missing character types).
        """
        feedback = []
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};:'\",.><?\/\\|`~]", password))

        variety_score = sum([has_lower, has_upper, has_digit, has_symbol])

        if not has_lower:
            feedback.append("Add lowercase letters.")
        if not has_upper:
            feedback.append("Add uppercase letters.")
        if not has_digit:
            feedback.append("Add numbers.")
        if not has_symbol:
            feedback.append("Add symbols (!@#$%^&*).")

        return variety_score, feedback

    def _has_common_patterns(self, password: str) -> List[str]:
        """
        Detect common weak patterns (sequences, repeats, common words).

        Args:
            password: Password to evaluate.

        Returns:
            List of detected weak patterns.
        """
        issues = []

        # Check for repeated characters (e.g., "aaa", "111")
        if re.search(r"(.)\1{2,}", password):
            issues.append("Avoid repeated characters (e.g., aaa, 111).")

        # Check for sequential patterns (e.g., "abc", "123", "qwerty")
        sequences = [
            "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk", "jkl",
            "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv",
            "uvw", "vwx", "wxy", "xyz", "123", "234", "345", "456", "567", "678",
            "789", "012", "qwerty", "asdfgh", "zxcvbn",
        ]
        for seq in sequences:
            if seq in password.lower():
                issues.append(f"Avoid keyboard sequences like '{seq}'.")
                break

        # Check for common years
        if re.search(r"(19|20)\d{2}", password):
            issues.append("Avoid using years (e.g., 1990, 2023).")

        return issues

    def _is_blacklisted(self, password: str) -> List[str]:
        """
        Check if password or its components are in the darklist.

        Args:
            password: Password to evaluate.

        Returns:
            List of blacklist matches.
        """
        issues = []
        password_lower = password.lower()

        # Direct match
        if password_lower in self.darklist:
            issues.append("This password is in a known breach or common password list.")

        # Check for common words within the password
        for word in self.darklist:
            if len(word) > 3 and word in password_lower:
                issues.append(f"Contains common word '{word}'. Use unique, non-dictionary words.")
                break

        return issues

    def evaluate_password(self, password: str) -> Dict:
        """
        Perform full evaluation of password strength.

        Args:
            password: Password to evaluate.

        Returns:
            Dictionary with rating, score, and feedback.
        """
        length_score, length_feedback = self._score_length(password)
        variety_score, variety_feedback = self._has_variety(password)
        pattern_issues = self._has_common_patterns(password)
        blacklist_issues = self._is_blacklisted(password)

        # Calculate total score (0-10 scale)
        base_score = (length_score * 2) + variety_score
        penalty = len(pattern_issues) + (len(blacklist_issues) * 2)
        total_score = max(0, base_score - penalty)

        # Determine rating
        if total_score < 3:
            rating = "Weak"
        elif total_score < 5:
            rating = "Fair"
        elif total_score < 7:
            rating = "Good"
        elif total_score < 9:
            rating = "Strong"
        else:
            rating = "Very Strong"

        # Compile all feedback
        all_feedback = []
        if length_score < 2:
            all_feedback.append(length_feedback)
        if variety_feedback:
            all_feedback.extend(variety_feedback)
        if pattern_issues:
            all_feedback.extend(pattern_issues)
        if blacklist_issues:
            all_feedback.extend(blacklist_issues)

        return {
            "password": password,
            "rating": rating,
            "score": total_score,
            "feedback": all_feedback if all_feedback else ["Password meets basic requirements."],
        }

    def check_passwords_from_file(self, filepath: str) -> None:
        """
        Load and evaluate passwords from a file (one per line).

        Args:
            filepath: Path to file containing passwords.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: {filepath} not found.")
            return

        print(f"\n{'='*70}")
        print(f"Password Strength Audit Report")
        print(f"{'='*70}\n")

        results = []
        for password in passwords:
            result = self.evaluate_password(password)
            results.append(result)
            self.stats["total"] += 1
            rating_key = result["rating"].lower().replace(" ", "_")
            if rating_key in self.stats:
                self.stats[rating_key] += 1

        # Print detailed results
        for idx, result in enumerate(results, 1):
            print(f"[{idx}] Password: {result['password']}")
            print(f"    Rating: {result['rating']} (Score: {result['score']}/10)")
            print(f"    Feedback:")
            for feedback in result["feedback"]:
                print(f"      • {feedback}")
            print()

        # Print summary
        self._print_summary()

    def _print_summary(self) -> None:
        """Print audit summary statistics."""
        print(f"\n{'='*70}")
        print(f"Summary")
        print(f"{'='*70}")
        print(f"Total passwords checked:    {self.stats['total']}")
        print(f"Very Strong:                {self.stats['very_strong']}")
        print(f"Strong:                     {self.stats['strong']}")
        print(f"Good:                       {self.stats['good']}")
        print(f"Fair:                       {self.stats['fair']}")
        print(f"Weak:                       {self.stats['weak']}")

        weak_fair_count = self.stats["weak"] + self.stats["fair"]
        if weak_fair_count > 0:
            pct = (weak_fair_count / self.stats["total"]) * 100 if self.stats["total"] > 0 else 0
            print(f"\n⚠️  Passwords needing improvement: {weak_fair_count} ({pct:.1f}%)")
        print(f"{'='*70}\n")


def main():
    """Main entry point for the password strength checker."""
    checker = PasswordChecker(darklist_path="wordlist.txt")
    checker.check_passwords_from_file("sample_passwords.txt")


if __name__ == "__main__":
    main()
