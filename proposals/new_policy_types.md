# Kyverno Design Proposal - New Policy Types

- **Authors**: [Mariam Fahmy](https://github.com/MariamFahmy98)
- **Created**: December 23th, 2024
- **Abstract**: New Policy Types for Kyverno

## Overview

- [Introduction](#introduction)
- [Motivation](#motivation)
- [Goals](#goals)
- [Validating Policy](#validating-policy)
  + [Match Resources](#match-resources)
    * [Kyverno Match Resources](#kyverno-match-resources)
    * [VAP Match Resources](#vap-match-resources)
    * [Any/All Resource Filters](#anyall-resource-filters)
    * [Mapping Kyverno to VAP](#mapping-kyverno-to-vap)
      - [Matching based on Annotations](#matching-based-on-annotations)
      - [Matching based on Roles and ClusterRoles](#matching-based-on-roles-and-clusterroles)
      - [Matching based on UserInfo](#matching-based-on-userinfo)
  + [Webhook Configuration](#webhook-configuration)
  + [ValidationAction and AuditAnnotations](#validationaction-and-auditannotations)
  + [ValidationFailureActionOverrides](#validationfailureactionoverrides)
  + [Auto-Gen Rules](#auto-gen-rules)
  + [External Data Sources](#external-data-sources)
  + [Built-in Variables](#built-in-variables)
  + [Policy Exceptions](#policy-exceptions)
  + [JSON Payloads](#json-payloads)

## Introduction

Kubernetes has adopted [CEL](https://github.com/google/cel-spec) as a language for user-defined custom policies via the [ValidatingAdmissionPolicy (VAP)](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/), [MutatingAdmissionPolicies (MAP)](https://kubernetes.io/docs/reference/access-authn-authz/mutating-admission-policy/) and in other areas like webhook match conditions, and CRD validations.

As a result, most Kubernetes administrators are becoming familiar with CEL and Kubernetes API objects like ValidatingAdmissionPolicy and MutatingAdmissionPolicy. However, these built-in Kubernetes policies have limitations.

This proposal introduces new policy types in Kyverno to complement and extend the functionality of Kubernetes' built-in admission control policies, creating a comprehensive Policy-as-Code framework.

## Motivation

While ValidatingAdmissionPolicies and MutatingAdmissionPolicies offer robust features, they fall short in addressing several critical use cases for Policy-as-Code. Below are the limitations and opportunities for improvement:

1. Data Lookups: The built-in policies cannot perform data lookups from the API server or external API endpoints.

2. Background Scanning: They do not support periodic scanning of resources.

3. Policy Reports: No integrated mechanism for generating reports.

4. Exception Management.

5. CLI for Pipelines: Lack of command-line tools to apply policies in CI/CD pipelines.

6. Image Verification: Cannot handle tasks like registry access, caching, and signature verification.

7. Resource Generation: No support for generating new resources.

8. Resource Cleanup: No built-in capabilities for resource cleanup.

Additionally, Kyverno has its own validation mechanisms, including `validate.pattern`, `validate.cel`, and `validate.deny`. These overlapping sub-types present an opportunity for streamlining and consolidation.

Currently, Kyverno defines validation, mutation, generation, and image verification rules within the ClusterPolicy CRD. CleanupPolicy, however, exists as a separate CRD. To improve maintainability, we propose migrating each policy rule type into its own CRD.

## Goals

This proposal aims to:

* Introduce new policy types to address the limitations outlined above.
* Simplify Kyverno’s existing rule sub-types by consolidating overlapping functionalities for easier maintenance and better user experience.
* Enable Kyverno policies to operate on any JSON payload, not just Kubernetes resources.

## Validating Policy

The new ValidatingPolicy CRD will replace the existing validation rules in the ClusterPolicy CRD. 

It will be an extension of the Kubernetes ValidatingAdmissionPolicy, with additional features like data lookups, background scanning, and policy reports.

The ValidatingPolicy CRD may look like the following:

```yaml=
apiVersion: kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: "demo-policy.example.com"
spec:
  failurePolicy: Fail
  failureAction: Enforce
  failureActionOverrides:
  - action: Audit
    namespaces:
      - test-ns-1
    namespaceSelector:
      matchExpressions:
        - key: app
          operator: In
          values:
          - development
  matchConstraints:
    resourceRules:
    - apiGroups:   ["apps"]
      apiVersions: ["v1"]
      operations:  ["CREATE", "UPDATE"]
      resources:   ["deployments"]
    excludeResourceRules:
    - apiGroups:     ["apps"]
      apiVersions:   ["v1"]
      operations:    ["CREATE", "UPDATE"]
      resources:     ["deployments"]
      resourceNames: ["testing"]
    objectSelector:
      matchLabels:
        app: critical
    namespaceSelector:
      matchLabels:
        app: critical		
  matchConditions:
    - name: 'exclude-kubelet-requests'
      expression: '!("system:nodes" in request.userInfo.groups)'
  validations:
    - expression: "object.spec.replicas > 50"
      messageExpression: "'Deployment spec.replicas set to ' + string(object.spec.replicas)"
  auditAnnotations:
    - key: "high-replica-count"
      valueExpression: "'Deployment spec.replicas set to ' + string(object.spec.replicas)"
```

### Match Resources

The structure and capabilities of Kyverno’s match resources differ significantly from those of VAPs. 

This section provides a detailed comparison and highlights how Kyverno’s structure can be mapped to VAPs’ match resources while documenting any limitations or differences.

#### Kyverno Match Resources

Kyverno’s match resources offer a highly flexible structure, allowing for granular resource selection using multiple criteria such as resource kinds, operations, names, namespaces, annotations, labels, roles, and subjects. 

Below is an example of a Kyverno `match` block:

```yaml=
match:
  any:
  - resources:
      kinds:
      - Deployment
      operations:
      - CREATE
      names:
      - "app"
      namespaces:
      - "default"
      annotations:
        "app.kubernetes.io/name": "nginx"
      selector:
        matchLabels:
          "app": "nginx"
      namespaceSelector:
        matchLabels:
          "app": "nginx"
    roles:
    - user-role
    clusterRoles:
    - cluster-admin
    subject:
    - kind: User
      name: mary@somecorp.com
```

Kyverno supports advanced matching capabilities, including:

1. Annotations and Labels: Use annotations and label selectors for fine-grained filtering.

2. Namespace Selector: Match resources within specific namespaces based on labels.

3. Roles and Subjects: Match requests based on user roles, cluster roles, or specific subjects such as users or service accounts.

#### VAP Match Resources

VAP’s match resources, defined under `matchConstraints`, follow a more structured but less flexible approach. 

Below is an example of a VAP match resource:

```yaml=
matchConstraints:
  resourceRules:
  - apiGroups:   ["apps"]
    apiVersions: ["v1"]
    operations:  ["CREATE", "UPDATE"]
    resources:   ["deployments"]
  objectSelector:
    matchLabels:
      app: critical
  namespaceSelector:
    matchLabels:
      app: critical
  matchPolicy: Exact
```

Key features of VAP’s match resources include:

1. Resource Rules: Define API groups, versions, operations, and resource types for matching.

2. Object Selector: Use label selectors to filter specific objects.

3. Namespace Selector: Match resources in namespaces based on labels.

4. Match Policy: Specify how to match incoming request. Allowed values: `Exact` or `Equivalent`.

#### Any/All Resource Filters
  
Kyverno provides flexible resource matching through the use of `any` and `all` filters. The `any` filter allows you to define multiple resource specifications, where a match occurs if any of the specified conditions are met **(OR logic)**. This means a resource will be matched if it satisfies at least one of the defined criteria. The `all` filter requires all specified conditions to be true for a match **(AND logic)**. This ensures a resource matches only if it satisfies every single criterion.

ValidatingAdmissionPolicies (VAPs), on the other hand, offer a less granular approach. The various fields within `spec.matchConstraints` (like `objectSelector` and `namespaceSelector`) are implicitly combined using **AND logic**. This means all these selectors must match for the VAP to apply to a resource. However, within the `spec.matchConstraints.resourceRules` field, multiple rules are **ORed**. This means the VAP will apply if the resource matches any of the defined resourceRules. 

#### Mapping Kyverno to VAP

##### Matching based on Annotations

Here is an example of a Kyverno rule that matches all Pods having `imageregistry: "https://hub.docker.com/"` annotations.

```yaml=
spec:
  rules:
    - name: match-pod-annotations
      match:
        any:
        - resources:
            annotations:
              imageregistry: "https://hub.docker.com/"
            kinds:
              - Pod
            operations:
            - CREATE
            - UPDATE
```

The equivalent VAP match resource would look like this:

```yaml=
spec:
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE", "UPDATE"]
        resources:   ["pods"]
  matchConditions:
    - name: 'match-pod-annotations'
      expression: >-
        object.metadata.?annotations[?'imageregistry'] == 'https://hub.docker.com/'
```

##### Matching based on Roles and ClusterRoles

Kyverno allows matching based on user roles and cluster roles. 

Here is an example of a Kyverno rule that matches all Pods being created by users with the `cluster-admin` role.

```yaml=
spec:
  rules:
    - name: match-pod-roles
      match:
        any:
        - resources:
            kinds:
            - Pod
          clusterRoles:
          - cluster-admin
```

Kubernetes VAPs do not support matching based on roles. We can introduce a CEL object `request.roles`/`request.clusterRoles` to represent the user roles and cluster roles. We can then use this object in the match expression to match the request based on the user roles/cluster roles. 

##### Matching based on UserInfo

Kubernetes VAPs allow matching based on `UserInfo` fields from the admission request like `username`, `uid`, `groups`, and `extra`. 

Below is an example of a VAP match resource that matches requests from the user.

```yaml=
spec:
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE", "UPDATE"]
        resources:   ["pods"]
  matchConditions:
    - name: 'check-username'
      expression: "request.userInfo.username == 'admin'"
    - name: 'check-uid'
      expression: "request.userInfo.uid == '014fbff9a07c'"
    - name: 'check-user-groups'
      expression: "request.userInfo.groups == ['system:authenticated', 'my-admin-group']"
    - name: 'check-extra'
      expression: "request.userInfo.extra == {'some-key': ['some-value1', 'some-value2']}"
```

Here is an example of a Kyverno rule that matches all Services being created by the user `dave` or `mariam`.

```yaml=
match:
  any:
  - resources:
      kinds:
      - Service
      operations:
      - CREATE
    subjects:
    - kind: User
      name: dave
    - kind: User
      name: mariam
```

The equivalent VAP match resource would look like this:

```yaml=
spec:
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE"]
        resources:   ["services"]
  matchConditions:
    - name: 'check-username'
      expression: "request.userInfo.username == 'dave' || request.userInfo.username == 'mariam'"
```

Here is an example of a Kyverno rule that matches all Pods being created by users whose names start with `not-`.

```yaml=
match:
  any:
  - resources:
      kinds:
      - Pod
    subjects:
    - kind: User
      name: not-?*
```

The equivalent VAP match resource would look like this:

```yaml=
spec:
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE"]
        resources:   ["pods"]
  matchConditions:
    - name: 'check-username'
      expression: "request.userInfo.username.startsWith('not-')"
```

Here is an example of a Kyverno rule that matches all Pods being created by `test-sa` ServiceAccount in the `test-ns` Namespace.

```yaml=
match:
  any:
  - resources:
      kinds:
      - Pod
  - subjects:
    - kind: ServiceAccount
      name: test-sa
      namespace: test-ns
```

The equivalent VAP match resource would look like this:

```yaml=
spec:
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE"]
        resources:   ["pods"]
  matchConditions:
    - name: 'check-username'
      expression: "request.userInfo.username == 'system:serviceaccount:test-ns:test-sa'"
```

Here is an example of a Kyverno rule that matches all Pods being created by users in the `dev` group.

```yaml=
  - match:
      all:
      - resources:
          kinds:
          - Pod
        subjects:
        - kind: Group
          name: dev
```

The equivalent VAP match resource would look like this:

```yaml=
spec:
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE"]
        resources:   ["pods"]
  matchConditions:
    - name: 'check-user-groups'
      expression: "request.userInfo.groups == ['dev']"
```

### Webhook Configuration

A ValidatingWebhookConfiguration can define multiple ValidatingWebhooks, each with its own specific settings. These settings include clientConfig, rules, timeoutSeconds, failurePolicy, namespaceSelector, objectSelector, matchPolicy, and matchConditions. For example:

```yaml=
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  labels:
    webhook.kyverno.io/managed-by: kyverno
  name: kyverno-resource-validating-webhook-cfg
webhooks:
- clientConfig:
    service:
      namespace: "example-namespace"
      name: "example-service"
    caBundle: <CA_BUNDLE>
  failurePolicy: Fail
  timeoutSeconds: 30
  matchPolicy: Equivalent
  matchConditions:
    - name: 'exclude-leases'
      expression: '!(request.resource.group == "coordination.k8s.io" && request.resource.resource == "leases")'
  objectSelector:
    matchLabels:
      foo: bar
  namespaceSelector:
    matchLabels:
      foo: bar
  rules:
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CONNECT
    - CREATE
    - DELETE
    - UPDATE
    resources:
    - '*'
    scope: 'Namespaced'
```

Kyverno allows users to configure some of these fields directly within a policy. For instance, timeoutSeconds, failurePolicy, and matchConditions can be set as follows:

```yaml=
spec:
  webhookConfiguration:
    timeoutSeconds: 30
    failurePolicy: Ignore
    matchConditions:
    - name: "select-namespace"
      expression: '(object.metadata.namespace == "cpol-fine-grained-match-conditions-ns")'
    - name: 'exclude-requests-by-groups'
      expression: '!("system:nodes" in request.userInfo.groups)' 
```

Kubernetes VAPs offer a `spec.matchConditions` field for fine-grained request filtering, similar to Kyverno's `preconditions`. This presents two options: utilize the VAP's matchConditions within the webhook configuration, or handle these conditions internally in the Kyverno engine.

Furthermore, VAPs offer a matchPolicy field (set to `Exact` or `Equivalent`) that governs how incoming requests are matched against rules. `Exact` requires precise matching, while `Equivalent` allows for matching across different API groups or versions. 

To maintain consistency and offer similar flexibility, the `ValidatingPolicy` CRD should introduce a `matchPolicy` field too. This presents two options: utilize this field within the webhook configuration, or handle it internally in the Kyverno engine.

### ValidationAction and AuditAnnotations

The supported `failureAction` in Kyverno policies is either of the following:

1. `Enforce`: It blocks the request on failure.
2. `Audit`: It doesn't block the request on failure. Instead, it returns a warning.

However, in VAPs the supported `validationActions` are:

1. `Deny`: Validation failure results in a denied request.
2. `Warn`: Validation failure is reported to the request client as a warning.
3. `Audit`: Validation failure is included in the audit event for the API request.

Therefore, `Enforce` in Kyverno corresponds to `Deny` in VAPs, and `Audit` in Kyverno corresponds to `Warn` in VAPs.

However, `Audit` in VAPs doesn't have an equivalent in Kyverno. It is responsible for generating an Audit event in the API server.

For example, if we have the following VAP:

```yaml=
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: "demo-policy"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups:   ["apps"]
      apiVersions: ["v1"]
      operations:  ["CREATE", "UPDATE"]
      resources:   ["deployments"]
  validations:
    - expression: "object.spec.replicas <= 5"
      message: "Deployment spec.replicas must be less than or equal to 5"
  auditAnnotations:
    - key: "high-replica-count"
      valueExpression: "'Deployment spec.replicas set to ' + string(object.spec.replicas)"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "demo-binding-test-1"
spec:
  policyName: "demo-policy"
  validationActions: [Warn, Audit]
```

The resulting audit event will look like this:

```
"annotations": {
  "authorization.k8s.io/decision": "allow",
  "authorization.k8s.io/reason": "RBAC: allowed by ClusterRoleBinding \"kubeadm:cluster-admins\" of ClusterRole \"cluster-admin\" to Group \"kubeadm:cluster-admins\"",
  "demo-policy/high-replica-count": "Deployment spec.replicas set to 7",
  "validation.policy.admission.k8s.io/validation_failure": "[{\"message\":\"failed expression: object.spec.replicas \\u003c= 5\",\"policy\":\"demo-policy\",\"binding\":\"demo-binding-test-1\",\"expressionIndex\":0,\"validationActions\":[\"Warn\",\"Audit\"]}]"
}
```

This feature can be used as report properties. The generated report will look like this:

```yaml=
results:
- message: Deployment spec.replicas must be less than or equal to 5.
  policy: demo-policy
  result: fail
  scored: true
  source: kyverno
  properties:
    high-replica-count: Deployment spec.replicas set to 7
```

Note that the `rule` field in the report result is omitted because we don't have any rules in the `ValidatingPolicy` CRD.

### ValidationFailureActionOverrides 

In Kyverno policies, the `failureActionOverrides` can be used to override the action in a specific Namespace as follows:

```yaml=
validate:
  failureAction: Audit
  failureActionOverrides:  ## why it is an array?
    - action: Enforce
      namespaces:
        - test-ns-1
        - test-ns-2
      namespaceSelector:
        matchExpressions:
          - key: app
            operator: In
            values:
            - development
```

In VAPs, the failure action is set in the policy binding via `spec.validationActions` field. 

In order to set different failure actions for different Namespaces, we need to create multiple bindings. 

For example to achieve the same functionality as above, we need to create two VAP bindings:

```yaml=
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "binding-1"
spec:
  policyName: "policy-1"
  validationActions: [Warn]
```

```yaml=
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "binding-2"
spec:
  policyName: "policy-1"
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchExpressions:
      - key: app
        operator: In
        values:
        - development
      - key: kubernetes.io/metadata.name
        operator: In
        values:
        - test-ns-1
        - test-ns-2
```

If multiple bindings match the request, the policy will be evaluated for each, and they must all pass evaluation for the policy to be considered passed.

### Auto-Gen Rules

The auto-gen rules for Pod controllers in the ValidatingPolicy might look like the following:

```yaml=
apiVersion: kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: "disallow-privilege-escalation"
spec:
  failurePolicy: Fail
  failureAction: Enforce
  matchConstraints:
    resourceRules:
    - apiGroups:   [""]
      apiVersions: ["v1"]
      operations:  ["CREATE", "UPDATE"]
      resources:   ["pods"]
  matchConditions:
    - name: "match condition"  
      expression: > 
        has(object.metadata.labels) && 
        has(object.metadata.labels.prod) && 
        object.metadata.labels.prod == 'true'
  validations:
    - expression: >- 
        object.spec.containers.all(container, has(container.securityContext) &&
        has(container.securityContext.allowPrivilegeEscalation) &&
        container.securityContext.allowPrivilegeEscalation == false)
```

The auto-generated rules will be shown under the `status` field as follows:

```yaml=
status:
  autogen:
    rules:
    - matchConstraints:
        resourceRules:
        - apiGroups:   ["apps"]
          apiVersions: ["v1"]
          operations:  ["CREATE", "UPDATE"]
          resources:   ["deployments", "statefulsets", "daemonsets", "replicasets"]
        - apiGroups:   ["batch"]
          apiVersions: ["v1"]
          operations:  ["CREATE", "UPDATE"]
          resources:   ["jobs"]
      matchConditions:
        - name: "match condition"  
          expression: > 
            has(object.spec.template.metadata.labels) && 
            has(object.spec.template.metadata.labels.prod) && 
            object.spec.template.metadata.labels.prod == 'true'
      validations:
        - expression: >- 
            object.spec.template.spec.containers.all(container, 
            has(container.securityContext) && 
            has(container.securityContext.allowPrivilegeEscalation) && 
            container.securityContext.allowPrivilegeEscalation == false)
    - matchConstraints:
        resourceRules:
        - apiGroups:   ["batch"]
          apiVersions: ["v1"]
          operations:  ["CREATE", "UPDATE"]
          resources:   ["cronjobs"]
      matchConditions:
        - name: "match condition"  
          expression: > 
            has(object.spec.jobTemplate.spec.template.metadata.labels) && 
            has(object.spec.jobTemplate.spec.template.metadata.labels.prod) && 
            object.spec.jobTemplate.spec.template.metadata.labels.prod == 'true'
      validations:
        - expression: >- 
            object.spec.jobTemplate.spec.template.spec.containers.all(container, 
            has(container.securityContext) && 
            has(container.securityContext.allowPrivilegeEscalation) && 
            container.securityContext.allowPrivilegeEscalation == false)
```

In case of generating Kubernetes ValidatingAdmissionPolicies, three VAPs, each with its own binding, are required. The first policy/binding targets Pods. The second targets Deployments, StatefulSets, DaemonSets, Jobs, and ReplicaSets. The third targets Jobs and CronJobs.

### External Data Sources

Kyverno currently supports four types of external data sources:

1. **ConfigMaps**: Used to fetch data stored in ConfigMap resources.
2. **Other Kubernetes Resources**: Allows querying any Kubernetes resource via the API server.
3. **Service API Calls**: Enables making HTTP calls to external services.
4. **OCI Image Metadata**: Retrieves image metadata from OCI registries.

The new `ValidatingPolicy` CRD will leverage the parameter resources mechanism offered by Kubernetes `ValidatingAdmissionPolicy` to access ConfigMaps and other Kubernetes resources. However, `ValidatingAdmissionPolicy` does not natively support service API calls or OCI image metadata. To address this, we propose the following approaches:

#### Approach 1: Data Pre-fetching and Storage in ConfigMaps

For external data sources not directly supported by `ValidatingAdmissionPolicy`, Kyverno can pre-fetch the necessary data and store it in a ConfigMap. This ConfigMap can then be accessed by the policy using the parameter resources mechanism.

**Process:**

1. **Data Fetching**: Kyverno fetches data from external services or OCI registries based on configurations defined in the policy or a separate CRD.
2. **Storage**: The fetched data is stored in a ConfigMap.
3. **Policy Execution**: The `ValidatingAdmissionPolicy` references this ConfigMap via `paramRef` in the `ValidatingAdmissionPolicyBinding`.

**Example:**

Let's say we have a policy that needs to validate if a container image is from an allowed registry list fetched from an external API.

1. **Data Fetching**: Kyverno makes an API call to `https://myregistryapi.com/allowed-registries` and retrieves a list of allowed registries.
2. **Storage**: Kyverno stores this list in a ConfigMap named `allowed-registries-config`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: allowed-registries-config
  namespace: kyverno
data:
  registries: |
    - registry.k8s.io
    - mycompany.com/registry
```

3. **Policy Execution**: The `ValidatingAdmissionPolicy` uses this ConfigMap:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: "check-allowed-registries"
spec:
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE"]
        resources:   ["pods"]
  validations:
    - expression: >-
        object.spec.containers.all(c, 
          params.data.registries.split(',').exists(reg, c.image.startsWith(reg))
        )
      message: "Image registry is not in the allowed list."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "check-allowed-registries-binding"
spec:
  policyName: "check-allowed-registries"
  paramRef:
    name: "allowed-registries-config"
    namespace: "kyverno"
  validationActions: [Deny]
```

**Pros:**

* Leverages existing `ValidatingAdmissionPolicy` features.
* Simplifies policy logic by abstracting data fetching.

**Cons:**

* Requires additional logic for data fetching and synchronization.
* May introduce latency if data needs to be refreshed frequently.
* Data in ConfigMaps might become stale if not updated regularly.

#### Approach 2: Upstream Enhancements to ValidatingAdmissionPolicies

Another approach is to propose enhancements to `ValidatingAdmissionPolicy` to support external data sources natively. This would involve extending the Kubernetes API to allow specifying external API endpoints or OCI registry details as parameters.

**Example Enhancement Proposal:**

Introduce a new field `externalParamRef` in `ValidatingAdmissionPolicyBinding` that allows referencing external data sources.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "check-allowed-registries-binding"
spec:
  policyName: "check-allowed-registries"
  externalParamRef:
    apiCall:
      url: "https://myregistryapi.com/allowed-registries"
      method: "GET"
      headers:
        - name: "Authorization"
          value: "Bearer <token>"
    # OR
    ociRegistry:
      registry: "myregistry.com"
      repository: "myrepo"
      tag: "latest"
  validationActions: [Deny]
```

**Pros:**

* Native support for external data sources in Kubernetes.
* Potentially more efficient and less complex than pre-fetching.

**Cons:**

* Requires significant changes to the Kubernetes API.
* Longer time to implement and gain community adoption.
* May introduce security concerns if not designed carefully.

#### Approach 3: Custom Admission Webhook with CEL Support

Instead of relying solely on `ValidatingAdmissionPolicy`, Kyverno could implement a custom admission webhook that supports CEL and provides built-in functions for accessing external data sources.

**Process:**

1. **Custom Webhook**: Kyverno runs as a webhook server.
2. **CEL Evaluation**: The webhook evaluates CEL expressions defined in policies.
3. **External Data Access**: Kyverno provides built-in CEL functions (e.g., `fetchURL()`, `getOCIMetadata()`) to fetch data from external sources during policy evaluation.

**Example:**

```yaml
apiVersion: kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: "check-allowed-registries"
spec:
  validations:
    - expression: >-
        let allowedRegistries = fetchURL("https://myregistryapi.com/allowed-registries");
        object.spec.containers.all(c, 
          allowedRegistries.exists(reg, c.image.startsWith(reg))
        )
      message: "Image registry is not in the allowed list."
```

**Pros:**

* Greater flexibility and control over policy execution.
* Can support any type of external data source.

**Cons:**

* Bypasses `ValidatingAdmissionPolicy` framework.
* Requires more custom implementation and maintenance.
* May have performance implications if not optimized.

#### Other Considerations

* **Caching**: Implement caching mechanisms to improve performance and reduce the load on external services.
* **Error Handling**: Define how policies should behave when external data sources are unavailable or return errors.
* **Security**: Securely manage credentials and access to external services.

### Built-in Variables

Kyverno has the following built-in variables:

1. `serviceAccountName`: when processing a request from `system:serviceaccount:nirmata:user1` Kyverno will store the value `user1` in the variable `serviceAccountName`. In CEL, there is no built-in variable for the service account name but it can be extracted from the `request.userInfo.username` field.

2. `serviceAccountNamespace`: when processing a request from `system:serviceaccount:nirmata:user1` Kyverno will store `nirmata` in the variable `serviceAccountNamespace`. In CEL, there is no built-in variable for the service account namespace.

3. `request.roles`: when processing a request from a user with roles `role1` and `role2`, Kyverno will store `role1` and `role2` in the variable `request.roles`. In CEL, there is no built-in variable for the user roles.

4. `request.clusterRoles`: when processing a request from a user with cluster roles `clusterRole1` and `clusterRole2`, Kyverno will store `clusterRole1` and `clusterRole2` in the variable `request.clusterRoles`. In CEL, there is no built-in variable for the cluster roles.

5. `images`: Kyverno extracts image data from the AdmissionReview request and makes this available as a variable named `images`. The following variables are set under `images`:

    1. registry
    2. path
    3. name
    4. tag
    5. digest
    6. reference
    7. referenceWithTag

    In CEL, there is no built-in variable for the image data. One possible solution is to generate CEL expression for the `images` variable within our engine that is efficiently loaded and used during resource validation. We can then utilize these expressions in the `variables` section when generating Kubernetes ValidatingAdmissionPolicies. The other solution is to create a dedicated CEL object for the `images` variable, and for this we need to identify the scenarios where the `images` variable is needed to determine if a dedicated CEL object is necessary.

### Policy Exceptions

PolicyExceptions in Kyverno are used to exclude resources from policy enforcement.

```yaml=
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: delta-exception
  namespace: delta
spec:
  exceptions:
  - policyName: disallow-host-namespaces
    ruleNames:
    - host-namespaces
    - autogen-host-namespaces
  match:
    any:
    - resources:
        kinds:
        - Pod
        - Deployment
        namespaces:
        - delta
        names:
        - important-tool*
  conditions:
    any:
    - key: "{{ request.object.metadata.labels.app || '' }}"
      operator: Equals
      value: busybox
```

To ensure compatibility with the new ValidatingPolicy type, several adjustments can be made:

1. `ruleNames`: This field is unnecessary, as ValidatingPolicies don't employ the concept of rules. This field should be removed from the PolicyException spec.

2. `match`: This field filters resources based on Kind. However, ValidatingPolicies utilize `matchConstraints` based on API groups, versions, operations, and resources. Therefore, the PolicyException's match field must be replaced with a matchConstraints field to align with this mechanism.

3. `conditions`: This field is used to match resources based on a set of conditions under `any`/`all` filters. Instead, we can leverage the `matchConditions` field, which uses CEL expressions.

The `PolicyException` can look like the following:

```yaml=
apiVersion: kyverno.io/v1alpha1
kind: PolicyException
metadata:
  name: delta-exception
  namespace: delta
spec:
  policyNames: 
  - disallow-host-namespaces
  matchConstraints:
    resourceRules:
    - apiGroups:   [""]
      apiVersions: ["v1"]
      operations:  ["CREATE", "UPDATE"]
      resources:   ["pods"]
  matchConditions:
    - name: 'match-pod-annotations'
      expression: > 
        has(object.metadata.labels.app) && 
        object.metadata.labels.app == 'busybox'
```

How can we generate Kubernetes ValidatingAdmissionPolicies based on Kyverno's ValidatingPolicy and PolicyException CRDs?

### JSON Payloads

