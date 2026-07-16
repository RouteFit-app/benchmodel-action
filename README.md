# BenchModel AI Code Review — GitHub Action

Review every pull request with the AI model of your choice, scored the way
[BenchModel](https://benchmodel.io) scores its public leaderboard: a finding
only counts when it lands on the actual defect, not when it drops a keyword.
Findings are posted as a PR comment. Optionally fail the check on high-severity
issues so it acts as a merge gate.

It's **bring-your-own-key**: the review runs on the provider key you've stored in
your BenchModel account, so you control cost and which model runs. This Action
just carries the diff there and the findings back.

## Setup (2 minutes)

1. **Store a provider key** in BenchModel (Settings → API keys), e.g. Anthropic,
   OpenAI, Gemini, or DeepSeek. This is the key the review runs on.
2. **Mint a BenchModel API token** (Settings → API tokens). It looks like
   `bm_...`. Copy it.
3. In your repo, add it as a secret: **Settings → Secrets and variables →
   Actions → New repository secret**, name `BENCHMODEL_TOKEN`, value the `bm_`
   token.
4. Add the workflow below at `.github/workflows/benchmodel.yml`.

## Workflow

```yaml
name: BenchModel review
on:
  pull_request:

permissions:
  contents: read          # read the PR diff
  pull-requests: write    # post the review comment

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: RouteFit-app/benchmodel-action@v1
        with:
          token: ${{ secrets.BENCHMODEL_TOKEN }}
          model: claude-sonnet-4-6      # any model you have a key for
          # fail-on: high               # uncomment to block merges on high-severity findings
```

## Inputs

| input | default | description |
|---|---|---|
| `token` | (required) | Your `bm_` BenchModel API token, from a repo secret. |
| `model` | `claude-sonnet-4-6` | Reviewer model id. Runs on your stored key for that provider. Current ids: `claude-opus-4-8`, `claude-sonnet-4-6`, `gpt-5.6`, `gemini-3.1-pro-preview`, `deepseek-v4-pro`. |
| `fail-on` | `none` | `none` (comment only), `high`, or `medium` — fail the check when a finding at that severity or higher is found, turning the review into a merge gate. |
| `max-chars` | `60000` | Skip the review if the diff is larger than this, to bound cost and latency. |
| `api-url` | BenchModel production | Override only if you self-host the API. |
| `github-token` | `${{ github.token }}` | Used to read the diff and post the comment. The default workflow token is fine. |

## What it does

On each `pull_request` event it reads the PR diff, sends it to your chosen model
through BenchModel, and posts a comment with a severity/location/issue table plus
collapsible suggested fixes. With `fail-on` set, it exits non-zero when a finding
meets the threshold, so branch protection can block the merge.

## Advisory by default

Out of the box the check is **advisory**: it posts the review as a comment and
passes (green), even when it flags a high-severity issue. That is intentional. A
green check means the review ran, not that the code is clean, so read the comment.

Blocking merges is a deliberate opt-in. AI reviewers are useful but not perfect,
so the sensible path is to run advisory for a while, see how the model's calls
land on your own code, and only then gate. When you trust it, uncomment
`fail-on: high` (blocks on high-severity findings only, ignoring medium and low
noise) and add the check to branch protection. Set `fail-on: medium` if you want
a stricter gate. There is no reason to force-block from day one.

## Notes

- **Cost is yours and bounded.** The review uses your provider key; `max-chars`
  caps the diff size so a giant PR can't run up a surprise bill.
- **Model choice is yours.** Point it at whichever model your own testing (or the
  [BenchModel leaderboard](https://benchmodel.io)) says is best for your stack.
- **Scoring standard.** BenchModel's grader requires a finding to identify the
  defect, not restate the diff or match a vocabulary word — the same standard that
  survived an external audit of the public benchmark.

Try it keyless first at [benchmodel.io/try](https://benchmodel.io/try).
