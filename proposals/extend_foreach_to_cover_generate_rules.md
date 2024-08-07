# Support `foreach` in Generate Rules

- **Authors**: [Mariam Fahmy](https://github.com/MariamFahmy98), [Shuting Zhao](https://github.com/realshuting)
- **Created**: Nov 11th, 2023
- **Updated**: Jul 18th, 2024
- **Abstract**: Supporting `foreach` in Generate Rules

# Table of Contents
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
[overview]: #overview
Generate rules are in charge of creating new resources. The rule can either generate the new resource using the `data` object or clone from an existing resource with the `clone` object. Currently, both generate patterns create single target resource. 

The `foreach` declaration is supported in validate and mutate rules to simplify rule applications of sub-elements in resource declarations. This proposal is to extend `foreach` support to offer flexible options for resource generation.

# Definitions
[definitions]: #definitions

1. Trigger: It refers to the resource responsible for triggering the generate rule as defined in a combination of `match` and `exclude` blocks.

2. Downstream/target: It refers to the generated resource(s).

3. Source: It refers to the clone source when cloning new resources from existing ones.

# Motivation
[motivation]: #motivation

There are some use cases where a single "trigger" resource should result in the creation of multiple downstream resources.

Use cases:
1. Generate a list of new `NetWorkPolicy` based on a comma separated string in an annotation using a `foreach` and `Split()`.
2. Migrate from ingress to Kubernetes Gateway API requires generating at least two resources: `Gateway` and `HTTPRoute`.
3. Create several `ProjectIamMember` Crossplane GCP CRs based on a comma-separated label of a namespace.
4. Clone the `Secret` to a list of `Namespace` looked up by the source `Secret`'s label.

# Proposal

Based on the use cases mentioned above, we can introduce `foreach` for generate rules in two phases:
- Phase 1: support the generation or cloning of a list of resources for each generation rule by adding `dataList` or `cloneList` to the generate pattern; 
- Phase 2: support iteration through the given list using the `foreach` declaration.

Let's break down each phase to following:

## Phase 1 - support `dataList` and `cloneList`

To allow generation of multiple downstream resources for a single trigger, `dataList` and `cloneList` can be added to `generate` pattern.

The following rule snippet showcases generation of a `NetworkPolicy` and a `ConfigMap` using `dataList`:
```yaml
spec:
  rules:
  - name: generate-multiple-targets
    match:
      any:
      - resources:
          kinds:
          - Namespace
    generate:
      dataList:
      - apiVersion: v1
        kind: NetworkPolicy
        name: default-networkpolicy
        namespace: "{{ request.object.metadata.name }}"
        data:
          spec:
            podSelector: {}
            policyTypes:
            - Ingress
            - Egress
      - apiVersion: v1
        kind: ConfigMap
        name: default-configmap
        namespace: "{{ request.object.metadata.name }}"
        data:
          foo: bar
```

The following rule clones a source secret `regcred` and a configmap `default-configmap` from `default` namespace to the new created namespace using `cloneList`. Note that the [cloneList](https://github.com/kyverno/kyverno/blob/main/api/kyverno/v1/common_types.go#L736) is already supported which allows cloning sources by label selectors. To make it backward compatible, this proposal introduces new `list` under `cloneList` pattern to provide flexibility when selecting sources.

```yaml
spec:
  rules:
  - name: clone-multiple-sources
    match:
      any:
      - resources:
          kinds:
          - Namespace
    generate:
      cloneList:
        list:
        - source:
            namespace: default
            name: default-regcred
            kind: v1
            apiVersion: Secret
          target:
            namespace: "{{ request.object.metadata.name }}"
            name: regcred
        - source:
            namespace: default
            name: default-configmap
            kind: v1
            apiVersion: ConfigMap
          target:
            namespace: "{{ request.object.metadata.name }}"
            name: cloned-configmap
```

## Phase 2 - support `foreach` declaration

In the second phase, the generate rule can be expanded to support `foreach` declaration in order to iterate through given list. This could be done by adding the `foreach` key under generate pattern, and a `list` attribute which is a JMESPath expression that defines the sub-elements it processes. For every `foreach` pattern, either `dataList` or `cloneList` will be supported.

The following example defines a generate rule which takes a list of namespaces, which is derived from a comma-separated label value, and creates networkpolicies into new namespaces.

Since the resource names for a kind needs to be unique within the same namespace, the user needs to define a dynamic name for the downstream resource, i.e., add `{{elementIndex}}` to the name.

```yaml
spec:
  rules:
  - name: generate-network-policies
    match:
      any:
      - resources:
          kinds:
          - Namespace
    generate:
      foreach:
        - list: request.object.metadata.labels.networkpolicies | split(@, ',')
          dataList:
            - apiVersion: v1
              kind: NetworkPolicy
              name: my-networkpolicy-{{ elementIndex }}
              namespace: "{{ request.object.metadata.name }}"
              data:
                spec:
                  podSelector: {}
                  policyTypes:
                  - Ingress
                  - Egress
```

This example takes a list of namespaces, which is looked up by the `apiCall`, and clones the `Secret` to corresponding namespaces:
```yaml
spec:
  rules:
  - name: clone-secret-to-multiple-namespace
    match:
      any:
      - resources:
          kinds:
          - Secret
          namespaces:
          - default
    context:
    - variable:
        name: selector
        jmesPath: request.object.metadata.labels.sync
        default: a=b
    - name: namespaces
      apiCall:
        urlPath: /api/v1/namespaces?labelSelector={{selector}}?limit=5
    generate:
      foreach:
        - list: "{{ namespaces }}"
          cloneList:
          - source:
              namespace: default
              name: regcred
              kind: v1
              apiVersion: Secret
            target:
              namespace: "{{ element }}"
              name: regcred
```

More examples using `foreach`:
1. Generate `ConfigMap` and `Secret` for each container:
```yaml
spec:
  rules:
  - name: generate-configmaps-and-secrets
    match:
      any:
      - resources:
          kinds:
          - Pod
    generate:
      foreach:
        - list: request.object.spec.containers
          dataList:
            - apiVersion: v1
              kind: ConfigMap
              name: my-configmap-{{ elementIndex }}
              namespace: "{{ request.object.metadata.namespace }}"
              data:
                foo: bar
            - apiVersion: v1
              kind: Secret
              name: my-secret-{{ elementIndex }}
              namespace: "{{ request.object.metadata.namespace }}"
              data:
                foo: bar
```

2. Generate `Gateway` and `HTTPRoute` from Ingress:
```yaml
spec:
  rules:
  - name: generate-gatewayapi
    match:
      any:
      - resources:
          kinds:
          - Ingress
    generate:
      foreach:
        - list: request.object.spec.rules
          dataList:
            - apiVersion: gateway.networking.k8s.io/v1beta1
              kind: HTTPRoute
              # the name must be unique
              name: httproute-{{ elementIndex }}
              namespace: "{{ request.object.metadata.namespace }}"
              data:
                spec:
                  hostnames: 
                    - '{{ element.host }}'
        - list: request.object.spec.ingressClassName
          dataList:
            - apiVersion: gateway.networking.k8s.io/v1beta1
              kind: Gateway
              name: gateway-{{ elementIndex }}
              data:
                spec:
                  gatewayClassName: '{{ element }}'
```

Note a generate rule allows only one of the following `data`, `clone`, `dataList` and `cloneList` to be declared.

## Support `context` and `preconditions` for each sub-element

Similar to mutate and validate `foreach`, the `context` and the `preconditions` attributes are supported for generate rules for finer conditional checks.

The following `foreach` rule looks up the label value from the incoming request, and creates a configmap for each container if the label matches static value `foo=bar`:

```yaml
spec:
  rules:
  - name: generate-gatewayapi
    match:
      any:
      - resources:
          kinds:
          - Pod
    generate:
      foreach:
      - list: request.object.spec.containers
        context:
        - variable:
            name: selector
            jmesPath: request.object.metadata.labels.sync
            default: a=b
        preconditions:
          all:
          - key: "{{selector}}"
            operator: Equals
            value: foo=bar
        dataList:
          - apiVersion: v1
            kind: ConfigMap
            name: my-configmap-{{ elementIndex }}
            namespace: "{{ request.object.metadata.namespace }}"
            data:
              foo: bar
```
# Implementation
tbd

# Drawbacks

N/A

# Alternatives

N/A

# Prior Art

N/A

# Unresolved Questions

