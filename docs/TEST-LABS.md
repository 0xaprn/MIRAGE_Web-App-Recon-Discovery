# Safe MIRAGE test environments

Use isolated, local-only intentionally vulnerable applications to test discovery behavior. Do not expose these containers to a public interface.

## OWASP Juice Shop — recommended first test

Juice Shop is a deliberately vulnerable, JavaScript-heavy application intended in part for evaluating security scanners. See the [OWASP project page](https://owasp.org/projects/juice-shop) and [OWASP developer guide](https://devguide.owasp.org/en/07-training-education/01-vulnerable-apps/01-juice-shop/).

Run it locally with Docker:

```bash
docker pull bkimminich/juice-shop
docker run --rm --name mirage-juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

In MIRAGE, scan:

```text
http://127.0.0.1:3000/
```

Start with the **Deep web mapping** profile. Inspect the asset inventory, API candidates, JavaScript references, forms and findings. Stop the container with Ctrl+C.

**Important limitation:** Juice Shop is a JavaScript-heavy SPA. MIRAGE 0.4.0 does static JavaScript inspection but does not execute the application in a browser or authenticate into it. Therefore it will not discover every client-side route or detect all of Juice Shop's intentionally vulnerable business logic. The scan is a test of current passive/read-only discovery and posture checks, not a complete Juice Shop challenge solver.

## OWASP crAPI — API mapping

crAPI is an intentionally vulnerable API-focused application. See the [OWASP Vulnerable Applications Directory entry](https://vwad.owasp.org/app/crapi/) and the [official project](https://github.com/OWASP/crAPI).

Follow the project's current Docker Compose instructions and bind exposed ports to `127.0.0.1` only. Scan the locally published web/API entry points individually. MIRAGE 0.4.0 can inventory reachable API paths and metadata but does not authenticate, submit state-changing requests, or validate authorization flaws.

## OWASP WebGoat — server-side training app

WebGoat is a deliberately insecure Java application maintained by OWASP. See the [OWASP project page](https://owasp.org/projects/webgoat) and [official repository](https://github.com/WebGoat/WebGoat).

The official Docker instructions bind its ports to localhost. Keep it isolated; the project warns that the training application is intentionally vulnerable. MIRAGE can map its reachable pages and identify observable response/configuration issues, but it does not complete lesson exercises or actively verify injection flaws.

## Interpreting results

- Assets are observations, not vulnerabilities.
- Findings are read-only security posture observations or NVD intelligence candidates.
- NVD keyword matches are not proof that a specific deployed build is affected.
- A zero-finding result means no configured check produced a supported observation; it does not mean the target is secure.
- Record the scan profile and limits when comparing results between runs.
