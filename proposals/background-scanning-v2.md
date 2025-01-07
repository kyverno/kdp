# Meta
[meta]: #meta
- Name: Background Scanning V2
- Start Date: Jan 07 2025
- Update data (optional): (fill in today's date: YYYY-MM-DD)
- Author(s): vishal-chdhry
- Supersedes: N/A

# Table of Contents
[table-of-contents]: #table-of-contents
- [Meta](#meta)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Definitions](#definitions)
- [Motivation](#motivation)
- [Proposal](#proposal)
- [Implementation](#implementation)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Prior Art](#prior-art)
- [Unresolved Questions](#unresolved-questions)

# Overview

This KDP proposes an enhancement for Kyverno's background scanning feature.

# Definitions

- **Background Scanning**: Background scanning is a kyverno feature which allows Kyverno to periodically scan existing resources and find if they match any validate or verifyImages rules.

# Motivation

- Why should we do this?
- What use cases does it support?
- What is the expected outcome?

# Proposal

## Approach 1: Use Cron to schedule periodic scans on each policy

Kubernetes has pod controller called CronJob which creates Jobs on a repeating schedule. According to Kubernetes documentation:

> CronJob is meant for performing regular scheduled actions such as backups, report generation, and so on.

This approach for scheduling scans can be used by Kyverno policies as follows:

```yaml
apiVersion: kyverno.io/v3alpha1
kind: ValidatingPolicy
metadata:
  name: "check-allowed-registries"
spec:
  scanSchedule: 0 * * * * # Run once an hour at the beginning of the hour
```

### Advantages:
- This approach creates a schedule relative to the time of day, unlike [`metav1.Duration`](https://github.com/kubernetes/apimachinery/blob/master/pkg/apis/meta/v1/duration.go#L27) (e.g. `2h`, `2m30s`) which is relative to a user defined start time. Cron makes it easy to understand the precise timing of scan.
- Cron allows complex conditions such as `0 15 10 ? * MON-FRI` (10:15 am every Monday, Tuesday, Wednesday, Thursday and Friday) or `0 15 10 ? * 6L` (10:15 am on the last Friday of every month) which is not possible using duration as interval.
- Kubernetes already has a standard implementation that uses cron, `CronJob` and has libraries that are well maintained.

### Disadvantages
- Requires more effort to understand compared to durations.

## Approach 2: Use duration to schedule periodic scans on each policy

This is similar to current approach used by Kyverno for `backgroundScanInterval` flag. This adds a new field in policy spec to specify scan interval per policy.

This approach for scheduling scans can be used by Kyverno policies as follows:

```yaml
apiVersion: kyverno.io/v3alpha1
kind: ValidatingPolicy
metadata:
  name: "check-allowed-registries"
spec:
  scanInterval: 2h # Run once every two hours
```

### Advantages:
- Simpler to understand and create compared to cron.

### Disadvantages
- Less expressive than cron.
- Requires a base start time to schedule scans, the base start time should be persisent across pod crashes.

# Implementation


This is the technical portion of the KDP, where you explain the design in sufficient detail.

The section should return to the examples given in the previous section, and explain more fully how the detailed proposal makes those examples work.

## Link to the Implementation PR
N/A

# Drawbacks

Why should we **not** do this?

# Alternatives

- What other designs have been considered?
- Why is this proposal the best?
- What is the impact of not doing this?

# Prior Art

Discuss prior art, both the good and bad.

# Unresolved Questions

- What parts of the design do you expect to be resolved before this gets merged?
- What parts of the design do you expect to be resolved through implementation of the feature?
- What related issues do you consider out of scope for this KDP that could be addressed in the future independently of the solution that comes out of this KDP?

