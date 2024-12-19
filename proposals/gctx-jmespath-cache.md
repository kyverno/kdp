# Meta

[meta]: #meta

- Name: Global Context Entry Caching Enhancements
- Start Date: 2024-12-17
- Update Date: 2024-12-19
- Author(s): @KhaledEmaraDev

# Table of Contents

[table-of-contents]: #table-of-contents

- [Meta](#meta)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Definitions](#definitions)
- [Motivation](#motivation)
- [Proposal](#proposal)
- [Implementation](#implementation)
- [Migration](#migration)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Prior Art](#prior-art)
- [Unresolved Questions](#unresolved-questions)
- [CRD Changes](#crd-changes)

# Overview

[overview]: #overview

This proposal aims to enhance the performance of Kyverno's Global Context Entry feature by introducing caching mechanisms for JMESPath expressions. Currently, these expressions are evaluated on every lookup, which is expensive. This proposal explores one approach: where JMESPath evaluation is performed at write time by storing projections of data in the `GlobalContextEntry` CRD. A projection is like a materialized view in databases, where it does some pre-computation by applying the JMESPath expression and storing its output in a new alias that can later be accessed from within contexts in Policies.

# Definitions

[definitions]: #definitions

- **Global Context Entry:** A Kyverno CRD that caches Kubernetes resources or API call results.
- **JMESPath:** A query language for JSON data, used here to extract specific parts of the returned API data or resource.
- **Write Time:** The time when data is initially stored or cached. In the case of the Global Context Entry this is the time when the data from Kubernetes or the API Call is retrieved.
- **Lookup Time:** The time when data is retrieved from a cache or source.
- **Projection**: A pre-computed and cached result of applying a JMESPath expression to the retrieved data within a GlobalContextEntry.

# Motivation

[motivation]: #motivation

- **Why should we do this?** Evaluating JMESPath expressions on every lookup is inefficient and can lead to performance bottlenecks, especially with complex expressions or frequent access. This impacts Kyverno's overall performance and scalability, particularly in larger clusters.
- **What use cases does it support?** This change will improve the performance of policies that utilize the Global Context Entry, especially those policies that use frequent lookups.
- **What is the expected outcome?** The expected outcome is improved policy performance due to less resource usage when making calls to the Global Context Entry.

# Proposal

[proposal]: #proposal

This proposal details a caching mechanism for the Global Context Entry feature. It aims to improve performance by reducing the frequency of JMESPath evaluations. This is achieved by performing JMESPath evaluation at write time and storing the results as a projection within the `GlobalContextEntry`.

**JMESPath Evaluation at Write Time with Projections**

In this approach, the `jmesPath` expression is moved from the `globalReference` context definition to the `GlobalContextEntry` CRD definition, as part of a new `projections` field. This means that when the GlobalContextEntry data is fetched and stored, the `jmesPath` expressions within each projection are applied **once** and the resulting data is cached under a specified alias.

```yaml
apiVersion: kyverno.io/v2alpha1
kind: GlobalContextEntry
metadata:
  name: deployments
spec:
  kubernetesResource:
    group: apps
    version: v1
    resource: deployments
    namespace: fitness
  projections:
    - name: length_of_deployments
      jmesPath: length(@)
    - name: first_deployment_name
      jmesPath: "[0].metadata.name"
```

or

```yaml
apiVersion: kyverno.io/v2alpha1
kind: GlobalContextEntry
metadata:
  name: deployments
spec:
  apiCall:
    urlPath: "/apis/apps/v1/namespaces/fitness/deployments?labelSelector=app=blue"
    refreshInterval: 10s
  projections:
    - name: length_of_deployments
      jmesPath: length(@)
```

The `globalReference` definition in the policy can now access the GlobalContextEntry and its projections using the dot notation.
Specifying the GlobalContextEntry name would return the entire data, while specifying the projection name would return the cached result of the JMESPath evaluation.

```yaml
context:
  - name: deployments
    globalReference:
      entry: deployments
  - name: deployment_count
    globalReference:
      entry: deployments.length_of_deployments
  - name: first_deployment_name
    globalReference:
      entry: deployments.first_deployment_name
```

**User Experience**

For existing users of the Global Context Entry, this change will involve moving the `jmesPath` expression from policy context to the `GlobalContextEntry` under the `projections` field. It simplifies the policy, as it only requires the GlobalContextEntry name and the projection name, and it's less verbose. New users will learn to configure the `jmesPath` within the GlobalContextEntry from the start. Multiple projections on the same GlobalContextEntry are now possible.

# Implementation

[implementation]: #implementation

1. **CRD Modification:** Modify the `GlobalContextEntry` CRD to include a `projections` field. Each entry in the `projections` field will include a `name` and a `jmesPath`.
2. **Data Retrieval:** When fetching data from Kubernetes or an API endpoint, the specified `jmesPath` expressions within the `projections` field are immediately applied to the retrieved data before caching it.
3. **Cache Storage:** The result of each `jmesPath` evaluation is stored in the cache, keyed by the Global Context Entry name and the projection name.
4. **Policy Context Retrieval:** When the `globalReference` is used, the cached result corresponding to the specified projection is returned.
5. **Data Refresh:** All projections for a `GlobalContextEntry` will be re-evaluated and the cache updated whenever the underlying data for the `GlobalContextEntry` changes.

**General Implementation Notes:**

- The cache implementation can use an in-memory cache.
- Error handling for invalid `jmesPath` expressions should be added, and these errors should be reported to the user via the Kyverno events and in the logs. If a `jmesPath` fails to evaluate, it will not be cached and the policy will fail with a specific error message indicating the projection could not be evaluated.

# Migration

[migration]: #migration

Requires changes to existing GlobalContextEntries and policies. It is not transparent and will require user intervention. Users will need to move the `jmesPath` to the GlobalContextEntry under the `projections` field, giving it a name, and then change the policy to reference the projection by name. This approach would also require a new Kyverno release to update the CRD to reflect this change.

# Drawbacks

[drawbacks]: #drawbacks

- The primary drawback is that it is less flexible than specifying the jmespath in the policy. Each projection in a `GlobalContextEntry` is a specific view of the data, determined by the `jmesPath`. If a policy needs a different `jmesPath` expression on the same data, a new projection must be added to the `GlobalContextEntry`. However, this is still an improvement, as many policies can then share the same projection.
- Requires user intervention and is not backwards compatible.

# Alternatives

[alternatives]: #alternatives

- **JMESPath Evaluation with TTL**: We could evaluate the `jmesPath` on every lookup but store the result in a cache with a `ttl`. The cache's key is a combination of the GlobalContextEntry's `name` and the `jmesPath` expression. The cache's value is the result of applying the `jmesPath` expression. This is more flexible but does not perform as well as the proposed approach.

# Prior Art

[prior-art]: #prior-art

- Kyverno already uses caching for Kubernetes resource lookups. This proposal extends that by integrating JMESPath results within the cache system.
- Other systems like data pipelines or caching services often employ similar strategies of evaluating expressions and results.

# Unresolved Questions

[unresolved-questions]: #unresolved-questions

- Should we have an additional global cache for cached data? It's currently per-controller, does this work?

# CRD Changes

[crd-changes]: #crd-changes

Requires a change to the GlobalContextEntry CRD and a new Kyverno release. A new `projections` field will be added to the spec.
