# MCAS Updates and Continuous Improvement

## Customer Updates centre

The Updates page reports the version configured on the MCAS server and displays release notes. MCAS is currently modelled as a centrally operated SaaS: customers do not download or install server code. The operator tests and deploys a release once, after which customers use the updated service.

The version is controlled by `MCAS_VERSION` (semantic version format, for example `1.1.0`). Bump it when preparing a centrally deployed release and update the release notes in `backend/app.py`. The Updates endpoint reports the server's configured release information; it does not independently query GitHub or prove deployment health.

## Customer feedback

Customers can submit bug reports, usability feedback, feature requests, security concerns and other product feedback. They can see only feedback associated with their own account. Administrators can review all submissions, update the workflow status and attach a note visible to the submitting customer.

Do not ask customers to submit passwords, API keys, tokens, private prospect records or sensitive personal information in feedback.

## AI-assisted improvement analysis

The Updates and Administrator Maintenance pages include an administrator-triggered feedback analysis workflow. A customer must explicitly tick the optional consent box when submitting feedback before the feedback text can be sent to the configured AI provider. Existing feedback and submissions without consent are excluded.

Before sending, MCAS removes common email-address, phone/number, URL and credential patterns from feedback titles and messages. This is best-effort redaction, not a guarantee that all personal or sensitive information is removed. The consent text asks customers not to include sensitive information. No customer email address, account ID, prospect record, saved draft, proposal, Gmail content or other workspace data is included in the AI request.

The administrator starts an analysis manually. MCAS analyses up to 50 newly opted-in feedback items, asks the configured OpenAI-compatible provider for structured recommendations and test ideas, validates the response shape, and stores a review in the MCAS database. Already-analysed feedback is not submitted again. The analysis endpoint is administrator-only and rate limited.

AI output is a proposal, not verified fact. It can be incomplete or wrong. An authorised operator must validate the issue, reproduce it, write or update tests, implement the code change on a feature branch, review the diff, wait for CI and CodeQL, test in staging, back up production data, and approve the hosted deployment. This workflow does not generate or execute code, create pull requests, merge branches, change security settings or deploy automatically.

## Administrator access

Set `MCAS_ADMIN_EMAILS` in the server's private environment to a comma-separated list of trusted administrator account email addresses:

```env
MCAS_ADMIN_EMAILS=operator@example.com,security@example.com
MCAS_VERSION=1.1.0
```

Restart MCAS after changing the environment. No administrator can add themselves through the application. Keep this list short and secure the associated email accounts with MFA. For production, configure it through the hosting provider's secret/environment settings rather than a committed file.

## Continuous maintenance

The repository already includes pull-request CI, CodeQL analysis and weekly Dependabot proposals. This release adds a scheduled weekly maintenance workflow that reruns tests and audits Python dependencies. These checks report findings; they do not automatically upgrade dependencies, merge pull requests or deploy production code.

Review every dependency update on a separate branch, inspect the diff, run CI and CodeQL, test in staging, take and verify a backup, then require an authorised human to approve deployment.

## Explicit safety boundaries

- AI feedback analysis creates structured improvement proposals only; it does not generate or execute code.
- No self-modifying production code.
- No automatic merge or production deployment.
- No automatic change to security configuration.
- No access to customer Gmail inboxes or automatic email sending.
- No cross-customer use of private feedback or workspace data.
- Administrator dashboard configuration indicators are not live scan results. Check GitHub Actions, CodeQL findings and hosting-provider backup/security status directly.
- Customer feedback counts are prioritisation signals, not proof of a widespread defect or permission to make changes without review.
