# Kyverno Design Proposal - Add mutation support in the CLI

Created: Aug 10th, 2024
Author: [Ammar Yasser](https://github.com/aerosouund)

- [Overview](#overview)
  * [Online Operation](#online-operation)
  * [Offline Operation](#offline-operation)
- [Proposal](#proposal)
- [Example](#example)
- [Implementation](#implementation)
  * [Resources obtained from a cluster](#resources-obtained-from-a-cluster)
  * [Resources passed from the CLI directly](#resources-passed-from-the-cli-directly)
  * [Previous attempts](#previous-attempts)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

## Overview

The Kyverno webhook controller runs as an admission controller in Kubernetes, mutating existing resources upon admission review. Such mutation is performed based on resource operations (CREATE/UPDATE/DELETE) via the webhook. This feature is currently available only in the webhook controller. The CLI has the following current behavior:

### Online Operation
An operation performed on a live Kubernetes cluster with the `--cluster` flag passed.

**Behavior**: No mutation occurs on the target resources fetched from the cluster. The output simply shows how many resources passed or failed, as typically seen in the CLI output:

`pass: 5, fail: 0, warn: 0, error: 0, skip: 0`

**Technical Explanation**: The CLI successfully fetches the correct resources and applies the mutation properly. However, what gets returned to the report generator is still the original resource.

`pkg/engine/mutation.go`:

```go
resource, ruleResp := e.invokeRuleHandler(
	ctx,
	logger,
	handlerFactory,
	policyContext,
	matchedResource,
	rule,
	engineapi.Mutation,
)

matchedResource = resource
```

### Offline Operation

An operation performed on static resources passed through the `--resource` flag or from a directory.

**Behavior**: The CLI outputs this message

```
Handler factory requires a client but a nil client was passed, likely due to a bug or unsupported operation.
```

**Technical Explanation**:

This error message was introduced as a safeguard for when the mutation engine tries to fetch resources from an uninitialized client (the object that interfaces with a Kubernetes cluster for CRUD operations) when not in cluster mode. Without this check, the CLI would panic. See [this issue](https://github.com/kyverno/kyverno/issues/6723) for additional context.
	

## Proposal

### apply

The apply command will receive an additional flag, `--target-resource`, which can be passed multiple times for individual resources. For example:

```bash
kyverno apply policy-with-mutate-existing.yaml --resource=trigger1.yaml --resource=trigger2.yaml --target-resource=resource1.yaml  --target-resource=resource2.yaml 
```

Or given a directory containing resources

```bash
kyverno apply policy-with-mutate-existing.yaml /path/to/trigger/resources --target-resource=/path/to/resources 
```

When this flag is passed but the policy or policies have no mutate-existing rules, the flag should be ignored. If the flag is not passed but the policy has mutate-existing rules, a warning should be generated indicating that no resources have been passed, and the rule evaluation should be SKIPPED. The target resource flag maps to the unchanged resource, and the apply command will output the mutated resource if successful.

### test

An extra key will be added to the test YAML definition to define the behavior of mutate-existing with the test command:

```yaml
apiVersion: cli.kyverno.io/v1alpha1
kind: Test
metadata:
  name: kyverno-test
policies:
  - <path/to/policy.yaml>
  - <path/to/policy.yaml>
resources:
  - <path/to/resource.yaml>
  - <path/to/resource.yaml>
exceptions:
  - <path/to/exception.yaml>
  - <path/to/exception.yaml>
targetResources: # This will be added
  - <path/to/unmutated/resource.yaml>
variables: variables.yaml # This will receive a new key for mutation target variables
userinfo: user_info.yaml
results: 
- policy: <name> 
  isValidatingAdmissionPolicy: false
  rule: <name>
  resources:
  - <namespace_1/name_1>
  - <namespace_2/name_2>
  patchedResources: <file_name.yaml> # Mutated resources will be specified here, separated by ---
  generatedResource: <file_name.yaml>
  - <path/to/patched/resource1.yaml>
  - <path/to/patched/resource2.yaml>
  cloneSourceResource: <file_name.yaml>
  kind: <kind>
  result: pass
```

The schema of the variables file will be changed as follows:

```yaml
apiVersion: cli.kyverno.io/v1alpha1
kind: Values
metadata:
  name: values
# existing keys
targetResources:
  - name: nginx-demo1
    namespace: test1
    values:
      request.operation: CREATE
  - name: nginx-demo2
    namespace: test2
    values:
      request.operation: UPDATE
```

The `targetResources` key will be added, with an array of objects containing three keys: name (string), namepace (string, optional) and values (a `map[string]interface{}`).

These additions will be optional and ignored if the policy does not include mutate-existing rules.

### Examples

This example adds data to a `ConfigMap` on namespace creation

`pol.yaml`
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: configmap-policy
spec:
  mutateExistingOnPolicyUpdate: true
  rules:
    - name: configmap-update
      match:
        any: 
        - resources:
            kinds:
            - Namespace
            operations:
              - "CREATE"
      mutate:
        targets:
        - apiVersion: v1
          kind: ConfigMap
          namespace: "test"
          name: "cm1"
        patchStrategicMerge:
          data:
            monitored-ns: "{{ request.object.metadata.name }}"
```

`ns.yaml`
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: staging
```

`cm.yaml`
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
  namespace: test
data: {}
```

Invocation:
`kyverno apply pol.yaml --resource=ns.yaml --target-resource=cm.yaml`

Should output:

```
Applying 1 policy rule(s) to 1 resource(s)...

mutate policy policy applied to test/ConfigMap/cm:
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
  namespace: test
data:
  monitored-ns: staging
---

pass: 1, fail: 0, warn: 0, error: 0, skip: 0 
```

---

This example adds the label `foo=bar` to deployments in the `secure` namespace in cluster mode

`pol.yaml`
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deployment-policy
spec:
  mutateExistingOnPolicyUpdate: true
  rules:
    - name: deployment-update
      match:
        any: 
        - resources:
            kinds:
            - Deployment
            namespaces:
              - "secure"
      mutate:
        targets:
        - apiVersion: apps/v1
          kind: Deployment
          namespace: "secure"
        patchStrategicMerge:
          metadata:
            annotations:
              foo: bar
```

Invocation:
`kyverno apply pol.yaml --cluster -n secure` 

Should output:

```
Applying 1 policy rule(s) to 1 resource(s)...

mutate policy policy applied to secure/Deployment/nginx-deployment:
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
	foo: bar <<< The mutated cluster resource
  // omitted fields
spec:
  progressDeadlineSeconds: 600
  replicas: 0
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: nginx
  strategy:
    rollingUpdate:
      maxSurge: 25%!
(MISSING)      maxUnavailable: 25%!
(MISSING)    type: RollingUpdate
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx:1.21.1
        imagePullPolicy: IfNotPresent
        name: nginx
        ports:
        - containerPort: 80
          protocol: TCP
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      terminationGracePeriodSeconds: 30
status:
  conditions:
  - lastTransitionTime: "2024-07-29T13:18:13Z"
    lastUpdateTime: "2024-07-29T13:18:19Z"
    message: ReplicaSet "nginx-deployment-5b4b69594c" has successfully progressed.
    reason: NewReplicaSetAvailable
    status: "True"
    type: Progressing
  - lastTransitionTime: "2024-07-29T18:25:49Z"
    lastUpdateTime: "2024-07-29T18:25:49Z"
    message: Deployment has minimum availability.
    reason: MinimumReplicasAvailable
    status: "True"
    type: Available
  observedGeneration: 2
---

pass: 1, fail: 0, warn: 0, error: 0, skip: 0 
```

## Implementation

There are two scenarios that need to be supported in the implementation:

### Resources obtained from a cluster

The `policyProcessor` of these resources will have a non nil client
`cmd/cli/kubectl-kyverno/commands/apply/command.go`:
```go
processor := processor.PolicyProcessor{
	Store: store,
	Policies: validPolicies,
	Resource: *resource,
	PolicyExceptions: exceptions,
	MutateLogPath: c.MutateLogPath,
	MutateLogPathIsDir: mutateLogPathIsDir,
	Variables: vars,
	UserInfo: userInfo,
	PolicyReport: c.PolicyReport,
	NamespaceSelectorMap: vars.NamespaceSelectors(),
	Stdin: c.Stdin,
	Rc: &rc,
	PrintPatchResource: true,
	Client: dClient, // THIS WONT BE NIL
	AuditWarn: c.AuditWarn,
	Subresources: vars.Subresources(),
	Out: out,
}
```
We need to return the actual mutated resource and modify the report generator to print it by changing the `matchedResource` variable to contain the mutated resource. Which can be obtained from the rule response: `ruleResp.patchedTarget`.

### Resources passed from the CLI directly

If the client is nil, the mutation engine should create an appropriate handler that doesn't fetch resources from the cluster but applies the mutation directly:

`pkg/engine/mutation.go`:

```go
handlerFactory := func() (handlers.Handler, error) {
if !rule.HasMutate() {
	return  nil, nil
}

if !policyContext.AdmissionOperation() && rule.HasMutateExisting() {
	if e.client == nil {
		return  nil, fmt.Errorf("Handler factory requires a client but a nil client was passed, likely due to a bug or unsupported operation.")
	}
	return mutation.NewMutateExistingHandler(e.client)
}
	return mutation.NewMutateResourceHandler()
}
```

A `MutateResourceHandler` should be returned in this case.
In case also simulation of a client update is required for non cluster operation then a kubernetes Fake client can be used to test if the mutation will fail using `k8s.io/client-go/dynamic/fake`, in this case the client initialization must account for this scenario.

```go
func (c *ApplyCommandConfig) initStoreAndClusterClient(store *store.Store, skipInvalidPolicies SkippedInvalidPolicies) (*processor.ResultCounts, []*unstructured.Unstructured, SkippedInvalidPolicies, []engineapi.EngineResponse, dclient.Interface, error) {

	// other logic

	var  err  error
	var  dClient dclient.Interface

	if !c.Cluster {
		dynamicClient := fake.NewSimpleDynamicClient(s) // s is a kubernetes scheme.Scheme
		dClient, err = dclient.NewClient(context.Background(), dynamicClient, kubeClient, 15*time.Minute)

		if err != nil {
			return  nil, nil, skipInvalidPolicies, nil, nil, err
		}
		return  nil, nil, skipInvalidPolicies, nil, dClient, err
	}
	// otherwise initialize a normal client
}
```
And this fake client will need to be passed the resources passed in the cli and created in its store to later be patched when the mutation engine returns the result


### Previous attempts

A previous [PR](https://github.com/kyverno/kyverno/pull/5220) tried to tackle this project before, the overall solution was to include a field in the `policyContext` that conveys if the command is a test command or something else. In case it is, the `loadTargets` method reads the resource from the context, where it exists as a field called `oldResource` and appends it to the resource list.

While this is still a viable approach it needs to be extended to be command agnostic, to be valid for `apply` and `test` as is the stated goal of the project. The overall idea that can be drawn from this is that the check for the nil client can be performed at the level of loading targets, this can be an alternative approach to what is proposed above.