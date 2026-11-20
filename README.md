# Ruvexara

A lightweight Python-based website security checker that identifies
common security misconfigurations and potentially exposed resources
through HTTP checks and JavaScript inspection.

> **Use only on websites you own or have explicit permission to
> assess.**

## Features

-   Checks common HTTP security headers.
-   Scans inline and linked JavaScript files for potentially exposed
    secrets.
-   Extracts API and admin-style endpoints from JavaScript.
-   Checks for publicly accessible source maps.
-   Inspects `robots.txt` and sitemap entries.
-   Checks for commonly exposed sensitive files.
-   Identifies potentially accessible admin and API routes.
-   Supports optional authenticated checks using cookies or custom
    headers.
-   Generates console, JSON, and HTML reports.

## Requirements

-   Python 3
-   `requests`

Install the dependency:

``` bash
python -m pip install requests
```

## Installation

Clone the repository:

``` bash
git clone https://github.com/muhmardini/Ruvexara
cd <repository-directory>
```

Alternatively, download `Ruvexara.py` directly.

## Usage

Run a basic scan:

``` bash
python Ruvexara.py https://example.com
```

Save the results as JSON and HTML:

``` bash
python Ruvexara.py https://example.com --json report.json --html report.html
```

### Options

  -----------------------------------------------------------------------
  Option                              Description
  ----------------------------------- -----------------------------------
  `url`                               Target website URL (required)

  `--cookie`                          Cookie header value for
                                      authenticated checks

  `--header`                          Additional HTTP header; can be
                                      supplied multiple times

  `--delay`                           Delay in seconds between HTTP
                                      request attempts (default: `0.3`)

  `--depth`                           JavaScript discovery depth
                                      (default: `1`)

  `--external`                        Include third-party JavaScript
                                      files

  `--json FILE`                       Save the report as JSON

  `--html FILE`                       Save the report as HTML

  `-h`, `--help`                      Show help information
  -----------------------------------------------------------------------

### Examples

Scan with a session cookie:

``` bash
python Ruvexara.py https://example.com --cookie "session=YOUR_SESSION_VALUE"
```

Scan with an authorization header:

``` bash
python Ruvexara.py https://example.com --header "Authorization: Bearer YOUR_TOKEN"
```

Adjust the request delay and JavaScript discovery depth:

``` bash
python Ruvexara.py https://example.com --delay 0.5 --depth 2
```

Include third-party JavaScript:

``` bash
python Ruvexara.py https://example.com --external
```

## Output

Findings are displayed in the terminal and can optionally be exported to
JSON or HTML.

Each finding includes:

-   **Severity:** `HIGH`, `MEDIUM`, `LOW`, or `INFO`
-   **Category:** The type of check that generated the finding
-   **Title:** A short description of the finding
-   **Location:** The affected URL or resource, when available
-   **Details:** Additional context

Detected secret-like values are masked in the report. Treat generated
reports as sensitive because they may contain information about the
target.

## Scope and Limitations

Ruvexara performs lightweight, predefined checks. It is not a full
vulnerability scanner or a substitute for a manual security assessment.

A reported result may require manual verification. In particular,
detecting a secret-like string or an accessible route does not by itself
confirm an exploitable vulnerability.

The checks are limited to the paths, headers, patterns, and discovery
methods implemented in the current version.

## Security and Responsible Use

-   Obtain authorization before scanning a target.
-   Stay within the approved scope.
-   Use an appropriate request delay and avoid disrupting production
    services.
-   Only provide credentials for systems you are authorized to test.
-   Store reports and session values securely.
-   Do not use discovered credentials or exposed resources without
    authorization.

## License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.
