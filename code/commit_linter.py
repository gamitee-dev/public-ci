from dataclasses import dataclass
from typing import Any, Dict, List
import json
import re
import sys

MAX_COMMIT_CHARS = 72
SUBJECT_REGEX = re.compile(r"^\S[\S ]*\S: \S[\S ]*\S\.$")
# URL regex taken from
# https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not
URL_REGEX = re.compile(
    r"^(?:http|ftp)s?://"  # http:// or https://
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain
    r"localhost|"  # localhost
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # or ip
    r"(?::\d+)?"  # optional port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)


@dataclass
class Author:
    name: str
    login: str
    email: str

    @staticmethod
    def parse(raw_data: Dict[str, Any]) -> "Author":
        return Author(name=raw_data["name"], login=raw_data["login"], email=raw_data["email"])


@dataclass
class Commit:
    authors: List[Author]
    subject: str
    body: str
    sha: str

    @staticmethod
    def parse(raw_data: Dict[str, Any]) -> "Commit":
        authors = [Author.parse(author) for author in raw_data["authors"]]
        return Commit(
            authors=authors,
            subject=raw_data["messageHeadline"],
            body=raw_data["messageBody"],
            sha=raw_data["oid"],
        )


@dataclass
class PullRequest:
    commits: List[Commit]
    base_ref_name: str
    head_ref_name: str
    title: str
    url: str

    @staticmethod
    def parse(raw_data: Dict[str, Any]) -> "PullRequest":
        commits = [Commit.parse(commit) for commit in raw_data["commits"]]
        return PullRequest(
            commits=commits,
            base_ref_name=raw_data["baseRefName"],
            head_ref_name=raw_data["headRefName"],
            title=raw_data["title"],
            url=raw_data["url"],
        )

    def validate_release_pr(self) -> bool:
        if self.base_ref_name != "master":
            return False

        if self.head_ref_name != "develop" and not self.head_ref_name.startswith("release/"):
            raise RuntimeError(
                "This seems to be a release PR but the base head is not develop or a release branch"
            )

        return True

    def is_dependabot_pr(self) -> bool:
        return all(
            all(author.login == "dependabot[bot]" for author in commit.authors)
            for commit in self.commits
        )


class CommitLinter:
    @classmethod
    def lint(cls, commit: Commit) -> None:
        if cls._is_ignore_commit(commit):
            return None

        if not all(
            author.email.lower().endswith("@joyned.co")
            or author.email.lower().endswith("@gamitee.com")
            or author.login == "gamitee-bot"
            for author in commit.authors
        ):
            raise RuntimeError("Author has non Joyned email address.")

        cls._validate_subject(commit.subject)

        cls._validate_body(commit.body)

        return None

    @classmethod
    def lint_title(cls, title: str) -> None:
        title_match = SUBJECT_REGEX.match(title)

        if not title_match:
            raise RuntimeError(
                "Pull request title must start with a title and a period after the message."
            )

        if len(title) > MAX_COMMIT_CHARS:
            raise RuntimeError(
                "Pull request title is longer than maximum length of "
                f"{MAX_COMMIT_CHARS} characters."
            )

        if not cls._is_only_ascii_character(title):
            raise RuntimeError("Pull request title has non-ASCII characters.")

    @staticmethod
    def _is_ignore_commit(commit: Commit) -> bool:
        ignored_subject_regexes = [
            r"^Merge pull request",
            r"^Merge branch",
            r"^Merge commit",
        ]

        return any(
            re.match(ignored_subject_regex, commit.subject)
            for ignored_subject_regex in ignored_subject_regexes
        )

    @classmethod
    def _validate_subject(cls, subject: str) -> None:
        subject_match = SUBJECT_REGEX.match(subject)
        if not subject_match:
            raise RuntimeError("Subject must start with a subject and a period after the message.")

        if len(subject) > MAX_COMMIT_CHARS:
            raise RuntimeError(
                f"Subject is longer than maximum length of {MAX_COMMIT_CHARS} characters."
            )

        if not cls._is_only_ascii_character(subject):
            raise RuntimeError("Subject has non-ASCII characters.")

    @classmethod
    def _validate_body(cls, body: str) -> None:
        if not body:
            return

        if not body.endswith(".") and not cls._is_ending_with_url(body):
            raise RuntimeError("Body doesn't end with a period.")

        for line in body.split("\n"):
            if len(line) > MAX_COMMIT_CHARS and not cls._is_ending_with_url(line):
                raise RuntimeError(
                    f"Body line is longer than maximum length of {MAX_COMMIT_CHARS} characters."
                )

            if not cls._is_only_ascii_character(line):
                raise RuntimeError("Body has non-ASCII character.")

    @staticmethod
    def _is_only_ascii_character(line: str) -> bool:
        return all(ord(character) < 128 for character in line)

    @staticmethod
    def _is_ending_with_url(line: str) -> bool:
        last_element = line.split(" ")[-1]
        return bool(re.match(URL_REGEX, last_element))


def main(raw_data: Dict[str, Any]) -> None:
    pull_request = PullRequest.parse(raw_data)
    print(f"Validating PR {pull_request.url}", flush=True)
    if pull_request.is_dependabot_pr():
        print("Dependabot PR, not checking commits", flush=True)
        return

    if pull_request.validate_release_pr():
        print("This is a release PR, not checking commits", flush=True)
        if not pull_request.title.startswith("Release: "):
            raise RuntimeError("Release pull request must start with 'Release: '")

        return

    for index, commit in enumerate(pull_request.commits):
        print(f'Linting commit {index} "{commit.subject}" ({commit.sha})', flush=True)
        CommitLinter.lint(commit)

    print("Commits are valid", flush=True)

    CommitLinter.lint_title(pull_request.title)
    print("Pull request is valid", flush=True)


if __name__ == "__main__":
    raw_data_json = json.loads(sys.stdin.buffer.read())
    try:
        main(raw_data_json)
    except RuntimeError as error:
        print(f"!! {error.args[0]}", flush=True)
        print("Linting failed", flush=True)
        sys.exit(1)
