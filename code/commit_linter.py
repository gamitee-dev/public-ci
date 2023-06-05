from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Literal, Optional, Set
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

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
LINKED_ISSUES_REGEX = re.compile(
    r"(?:(?:close|resolve)[sd]?|fix|fixe[sd])\s+"
    r"(?:(?:(?P<owner1>[a-z0-9-_]+)\/(?P<repo1>[a-z0-9-_]+))?"
    r"#|https:\/\/github\.com\/"
    r"(?P<owner2>[a-z0-9-_]+)\/(?P<repo2>[a-z0-9-_]+)\/issues\/)(?P<number>\d+)",
    re.IGNORECASE,
)
PULL_REQUEST_URL_PATTERN = re.compile(
    r"https\:\/\/github\.com\/(?P<owner>[\w-]+)\/(?P<repo>[\w-]+)\/pull\/\d+$"
)
BACKMERGE_PR_TITLE_PATTERN = re.compile(r"^Release: .* backmerge\.$")

# https://dev.to/bowmanjd/http-calls-in-python-without-requests-or-other-external-dependencies-5aj1
@dataclass
class HttpResponse:
    body: str
    headers: Dict[str, str]
    status: int
    error_count: int = 0

    def json(self) -> Dict[str, Any]:
        return json.loads(self.body)


def request(
    url: str,
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET",
    data: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> HttpResponse:
    request_data = None

    final_headers = {"accept": "application/json", **(headers or {})}

    final_url = url
    if params:
        final_url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    if data:
        request_data = json.dumps(data).encode()
        final_headers["content-type"] = "application/json; charset=UTF-8"

    httprequest = urllib.request.Request(
        final_url, data=request_data, headers=final_headers, method=method
    )

    try:
        with urllib.request.urlopen(httprequest) as httpresponse:
            return HttpResponse(
                headers=dict(httpresponse.headers),
                status=httpresponse.status,
                body=httpresponse.read().decode(httpresponse.headers.get_content_charset("utf-8")),
            )
    except urllib.error.HTTPError as error:
        return HttpResponse(
            body=str(error.reason),
            headers=dict(error.headers),
            status=error.code,
        )


@dataclass
class GithubIssue:
    number: int
    owner: str
    repo: str
    state: Literal["open", "closed"]
    title: str
    labels: Set[str]

    def display(self) -> str:
        return f"{self.owner}/{self.repo}#{self.number}: {self.title}"


class GithubClient:
    def __init__(self, token: str) -> None:
        self._token = token

    def get_issue(self, owner: str, repo: str, number: int) -> GithubIssue:
        response = self._request(f"/repos/{owner}/{repo}/issues/{number}")

        data = response.json()

        return GithubIssue(
            number=number,
            owner=owner,
            repo=repo,
            state=data["state"],
            title=data["title"],
            labels={label["name"] for label in data["labels"]},
        )

    def _request(
        self, path: str, method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET"
    ) -> HttpResponse:
        url = f"https://api.github.com{path}"
        headers = {"authorization": f"token {self._token}"}

        response = request(url=url, method=method, headers=headers)
        if not 200 <= response.status < 300:
            print(response, flush=True)
            raise RuntimeError("Invalid response from github")

        return response


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


@dataclass(repr=False)
class IssueDetails:
    number: int
    owner: str
    repo: str

    def display(self) -> str:
        return f"{self.owner}/{self.repo}#{self.number}"


@dataclass
class PullRequest:
    commits: List[Commit]
    base_ref_name: str
    head_ref_name: str
    title: str
    url: str
    body: str

    @staticmethod
    def parse(raw_data: Dict[str, Any]) -> "PullRequest":
        commits = [Commit.parse(commit) for commit in raw_data["commits"]]
        return PullRequest(
            commits=commits,
            base_ref_name=raw_data["baseRefName"],
            head_ref_name=raw_data["headRefName"],
            title=raw_data["title"],
            url=raw_data["url"],
            body=raw_data["body"],
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

    @property
    def owner(self) -> str:
        return PULL_REQUEST_URL_PATTERN.match(self.url)["owner"]  # type: ignore

    @property
    def repo(self) -> str:
        return PULL_REQUEST_URL_PATTERN.match(self.url)["repo"]  # type: ignore

    def get_linked_issues(self) -> Generator[IssueDetails, None, None]:
        default_owner = self.owner
        default_repo = self.repo

        for body_line in self.body.split("\n"):
            for match in LINKED_ISSUES_REGEX.finditer(body_line.strip()):
                yield IssueDetails(
                    number=int(match["number"]),
                    owner=(match["owner1"] or match["owner2"] or default_owner),
                    repo=(match["repo1"] or match["repo2"] or default_repo),
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
            or author.login == "tomerle"
            for author in commit.authors
        ):
            raise RuntimeError("Author has non Joyned email address, and is not tomerle. ;)")

        cls._validate_subject(commit.subject)

        cls._validate_body(commit.body)

        return None

    @classmethod
    def lint_title(cls, title: str) -> None:
        title_match = SUBJECT_REGEX.match(title)

        if not title_match:
            raise RuntimeError(
                "Pull request title must start with a subject and a period after the message. "
                "(in the same format as commit subjects)."
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


def validate_linked_issues(pull_request: PullRequest, github_client: GithubClient) -> None:
    print("Checking linked issues", flush=True)
    linked_issues = list(pull_request.get_linked_issues())
    if not linked_issues:
        raise RuntimeError("No linked issues were found in this pull request")

    for linked_issue in linked_issues:
        issue = github_client.get_issue(
            owner=linked_issue.owner, repo=linked_issue.repo, number=linked_issue.number
        )

        if issue.state != "open":
            raise RuntimeError(f"Issue {issue.display()} is not open")

        print(f"VALID: {issue.display()}", flush=True)


def main(raw_data: Dict[str, Any], github_token: str, only_master: bool) -> None:
    pull_request = PullRequest.parse(raw_data)
    print(f"Validating PR {pull_request.url}", flush=True)
    if pull_request.is_dependabot_pr():
        print("Dependabot PR, not checking commits", flush=True)
        return

    if not only_master and pull_request.validate_release_pr():
        print("This is a release PR, not checking commits", flush=True)
        if not pull_request.title.startswith("Release: "):
            raise RuntimeError("Release pull request must start with 'Release: '")

        return

    if (
        not only_master
        and raw_data["baseRefName"] == "develop"
        and raw_data["headRefName"] == "master"
    ):
        print("This is a backmerge PR, not checking commits", flush=True)
        if not BACKMERGE_PR_TITLE_PATTERN.match(pull_request.title):
            raise RuntimeError(
                f"Backmerge pull request must match {BACKMERGE_PR_TITLE_PATTERN.pattern}"
            )

        return

    for index, commit in enumerate(pull_request.commits):
        print(f'Linting commit {index} "{commit.subject}" ({commit.sha})', flush=True)
        CommitLinter.lint(commit)

    print("Commits are valid", flush=True)

    CommitLinter.lint_title(pull_request.title)
    print("Pull request is valid", flush=True)

    github_client = GithubClient(github_token)
    validate_linked_issues(pull_request, github_client)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Validate a pull request and its commit are per spec"
    )
    parser.add_argument("--token", help="The token to access github", required=True)
    parser.add_argument(
        "--only_master",
        help="Does this repository operate with only the master branch",
        action="store_true",
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        help="The file from github CLI with details of the PR",
        type=argparse.FileType("r"),
        default=sys.stdin,
    )

    args = parser.parse_args()
    raw_data_json = json.loads(args.input_file.buffer.read())

    try:
        main(raw_data_json, args.token, args.only_master)
    except RuntimeError as run_error:
        print(f"!! {run_error.args[0]}", flush=True)
        print("Linting failed", flush=True)
        sys.exit(1)
