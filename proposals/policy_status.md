# Meta

[meta]: #meta

- Name: Policy Status Readiness Evaluation
- Start Date: 2024-12-10
- Update Date: 2024-12-20
- Author(s): @KhaledEmaraDev

# Table of Contents

[table-of-contents]: #table-of-contents

- [Meta](#meta)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Definitions](#definitions)
- [Motivation](#motivation)
- [Proposal](#proposal)
  - [Ready Column Modification](#ready-column-modification)
  - [Dependency Matrix](#dependency-matrix)
- [Implementation](#implementation)
- [Migration](#migration-optional)
- [Alternatives](#alternatives)
- [CRD Changes](#crd-changes-optional)

# Overview

[overview]: #overview

This proposal introduces a new system for Kyverno to report the operational readiness of its policies. The system provides detailed status conditions for each policy, indicating whether webhooks are configured correctly (for Admission controllers), if the policy is loaded in Kyverno's cache, and if Kyverno has the necessary RBAC permissions to enforce it. Additionally, it proposes a modification to the `kubectl` output to display the number of ready conditions over the total number of relevant conditions. This will enhance troubleshooting, improve reliability, and provide better control over Kyverno's operation.

# Definitions

[definitions]: #definitions

- **Policy:** A set of rules in Kyverno that define desired configurations or behaviors for Kubernetes resources.
- **Webhook:** A mechanism in Kubernetes that allows external services (like Kyverno) to intercept and potentially modify API requests.
- **Admission Controller:** A type of Kyverno controller that intercepts and processes API requests before they are persisted to the Kubernetes cluster.
- **Background Controller:** A type of Kyverno controller that processes resources after they are created or updated.
- **Cache:** An internal data store used by Kyverno to quickly access frequently used information, such as policies.
- **RBAC (Role-Based Access Control):** A Kubernetes system for controlling who can access and modify resources.
- **CRD (Custom Resource Definition):** A way to extend Kubernetes with custom resource types.
- **NotReady:** A condition type that indicates that the specific sub-system is not ready and needs attention.

# Motivation

[motivation]: #motivation

- **Why should we do this?** Currently, diagnosing issues with Kyverno policies can be challenging due to limited status information. This lack of clarity leads to wasted time and effort during troubleshooting.
- **What use cases does it support?**
  - Quickly identifying the root cause of policy failures (e.g., webhook misconfiguration, missing permissions).
  - Automating monitoring and alerting based on policy readiness.
  - Improving the overall reliability of policy enforcement.
  - Gaining a better understanding of Kyverno's operational state.
- **What is the expected outcome?** Clear, actionable status information for each policy will enable users to quickly resolve issues, prevent policy deployment failures, and ensure that policies are enforced as intended. The modification to the `kubectl` output will provide a quick overview of policy readiness at a glance.

# Proposal

[proposal]: #proposal

This proposal introduces new status conditions to the Kyverno Policy CRD. These conditions will track the following:

- `WebhookConfigured`: Indicates whether the webhooks required for the policy are set up correctly. Relevant only for Admission controllers.
- `CachePresence`: Indicates whether the policy has been successfully loaded into Kyverno's internal cache.
- `RBACPermissions`: Indicates whether Kyverno has the necessary RBAC permissions to enforce the policy.

Each condition will have a status of `True` or `False`. If a condition's type is `NotReady` and the status is `False`, the policy will fail to apply unless explicitly configured otherwise through `validationFailureActionOverrides`. A condition may not be present if it's not relevant to the policy.

**Example:**

A user deploys a new policy that requires specific RBAC permissions. After deployment, they check the policy status:

```
kubectl describe policy my-policy

...
Status:
  Conditions:
    - Type: WebhookConfigured
      Status: True
      Reason: WebhookFound
      Message: Webhook configuration found and valid.
    - Type: CachePresence
      Status: True
      Reason: PolicyLoaded
      Message: Policy loaded into cache.
    - Type: RBACPermissions
      Status: False
      Reason: NotReady
      Message: Missing required RBAC permissions for Kyverno service account.
```

In this example, the user can immediately see that the `RBACPermissions` condition is `False` and the message indicates missing permissions. They can then grant the required permissions to resolve the issue.

**Error Messages:**

- WebhookConfigured:
  - `False`: "Webhook configuration not found or invalid: \[error details]."
- CachePresence:
  - `False`: "Policy not loaded into cache: \[error details]."
- RBACPermissions:
  - `False`: "Missing required RBAC permissions for Kyverno service account: \[list of missing permissions]."

## Ready Column Modification

[ready-column-modification]: #ready-column-modification

This proposal also suggests modifying the `READY` column in the `kubectl get policy` output. Instead of a simple boolean value, it will display the number of ready conditions over the total number of relevant conditions for the policy. For example:

```
NAME         BACKGROUND   VALIDATE ACTION   READY
my-policy    true         Audit             2/3
```

In this example, `2/3` indicates that two out of three relevant status conditions are `True`. This provides a quick overview of policy readiness without needing to describe each policy.

## Dependency Matrix

[dependency-matrix]: #dependency-matrix

The following matrix outlines the required status conditions for each combination of Kyverno controller type and rule type:

| Controller Type | Rule Type          | WebhookConfigured | CachePresence | RBACPermissions |
| :-------------- | :----------------- | :---------------- | :------------ | :-------------- |
| Admission       | Standard Mutate    | Required          | Required      | Not Applicable  |
| Admission       | Validate           | Required          | Required      | Not Applicable  |
| Admission       | Image Verification | Required          | Required      | Not Applicable  |
| Background      | Mutate Existing    | Not Applicable    | Required      | Required        |
| Background      | Generate           | Not Applicable    | Required      | Required        |

# Implementation

[implementation]: #implementation

This new system will significantly simplify the implementation of Kyverno controllers. Each controller will be responsible for managing a specific status condition, leading to more modular and maintainable code:

- **Webhook Controller:** This controller will solely manage the `WebhookConfigured` status condition. It will check for the existence and validity of the required webhooks and update the condition accordingly.
- **Policy Cache:** This controller will manage the `CachePresence` status condition. It will ensure that policies are loaded into the cache and update the condition based on the success or failure of this operation.

**Benefits of this Approach:**

- **Simplified Logic:** Each controller has a single, well-defined responsibility, making the code easier to understand, debug, and maintain.
- **Reduced Complexity:** There's no need for complex logic to handle multiple conditions within a single controller.
- **Improved Testability:** Each controller can be tested independently, ensuring the accuracy of its specific status condition.
- **Clearer Error Isolation:** If a specific condition is `False`, it's immediately clear which controller (and therefore which part of the system) needs attention.

This modular design will improve the overall robustness and maintainability of Kyverno.

# Migration

[migration-optional]: #migration-optional

This change is backward compatible. Existing tools that monitor policy status will continue to work, although they won't be able to take advantage of the new, detailed status conditions or the modified `READY` column. To fully leverage the new system, monitoring tools should be updated to check for the new status conditions (`WebhookConfigured`, `CachePresence`, `RBACPermissions`).

# Alternatives

[alternatives]: #alternatives

- **Single Overall Status:** We considered a single "Ready" status, but this was deemed insufficient for detailed troubleshooting.

# CRD Changes

[crd-changes-optional]: #crd-changes-optional

The `Policy` CRD's status section will be updated to include the new status conditions:

```yaml
status:
  conditions:
    - type: WebhookConfigured
      status: True|False
      reason: <Reason>
      message: <Detailed message>
    - type: CachePresence
      status: True|False
      reason: <Reason>
      message: <Detailed message>
    - type: RBACPermissions
      status: True|False
      reason: <Reason>
      message: <Detailed message>
```
