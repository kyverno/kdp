# Meta
[meta]: #meta
- Name: (Target Configuration CRD for policy reporter)
- Start Date: (2025-01-14)
- Author(s): (aerosouund)

# Table of Contents
[table-of-contents]: #table-of-contents
- [Meta](#meta)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Proposal](#proposal)
- [Implementation](#implementation)
- [Unresolved Questions](#unresolved-questions)

# Overview

The [policy reporter](https://github.com/kyverno/policy-reporter) takes in configuration for targets that it will send policy reports to through a flag `--config` which points to a file that can have a structure which is documented [here](https://kyverno.github.io/policy-reporter/core/targets). This document aims to define a CRD that will be used to provide the same functionality as this config file. giving administrators the ability to manage targets with this CRD.

A single CRD equals exactly one target. For example if you want to send to multiple slack channels, you need a CRD per channel


# Proposal

The CRD is proposed to have the following structure. The resource is non namespaced, and by default applies to all existing namespaces.

```yaml
apiVersion: policyreporter.io/v1alpha1
kind: TargetConfig
metadata:
  name: test
status:
 sendStatus:
 - eventID: 179db659-a29f-42c5-a9c2-4106d01ea339
   succeeded: true
   messagee: Send OK
 - eventID: 179db759-a22t-4hf5-al12-4106d01hdbn8
   succeded: false
   message: Got response 403
 conditions:
  - type: InSync
    status: "True"
    reason: SendReportSuccess
    message: "Sent with report with status 200"
    lastTransitionTime: "2025-01-07T14:00:00Z"
spec:
  targetType: string
  config: 
    filter:
      namespaces:
        include: ["team-a-*"]
      priorities:
        exclude: ["info", "debug"]
      policies:
        include: ["require-*"]
    # immutable field
    secretRef: string
    minimumSeverity: string
    skipExistingOnStartup: bool
```

The `sendStatus` field shows the last 3 or 4 sends as a summmary for the admin.

The conditions can be one of `InSync`, `OutOfSync`, `Unavailable`. Each of them means:
1- `InSync`: The target is active and all the reports that should be sent to it are sent
2- `OutOfSync`: The last send was successful but there are new reports to be sent to the target
3- `Unavailable`: The last send errored
4- `Invalid`: The config couldn't be parsed into the config schema expected by a target of the same type


# Examples

S3:

```yaml
apiVersion: policyreporter.io/v1alpha1
kind: TargetConfig
metadata:
  name: s3-target
spec:
  targetType: s3
  config:
    endpoint: 'https://s3.amazonaws.com'
    region: 'eu-west-1'
    bucket: 'policy-reporter'
    accessKeyId: 'redacted'
    secretAccessKey: 'redacted'
    minimumSeverity: warning
    skipExistingOnStartup: true
```

Slack (Inline):

```yaml
apiVersion: policyreporter.io/v1alpha1
kind: TargetConfig
metadata:
  name: slack-target
spec:
  targetType: slack-inline
  config:
    minimumSeverity: warning
    skipExistingOnStartup: true
    webhook: "https://hooks.slack.com/services/456..."
    filter:
      namespaces:
        include: ["team-b-*"]
```

Slack (Channel):

```yaml
apiVersion: policyreporter.io/v1alpha1
kind: TargetConfig
metadata:
  name: slack-target
spec:
  targetType: slack-channel
  config:
   skipExistingOnStartup: false
   secretRef: "team-a-slack-webhook"
    filter:
      namespaces:
        include: ["team-a-*"]
```


# Implementation

The new CRD will have an informer. On receiving an event, a new `Target` will be created and added to the collection struct saved by the resolver.


```golang
type Resolver struct {
  ...
	targetClients      *target.Collection // this is what gets appended to
  ...
}
```

The new informer will be introduced in the client `Sync` method

```golang
func (k *k8sPolicyReportClient) Sync(stopper chan struct{}) error {
	factory := metadatainformer.NewSharedInformerFactory(k.metaClient, 15*time.Minute)

	var cpolrInformer cache.SharedIndexInformer

	polrInformer := k.configureInformer(factory.ForResource(polrResource).Informer())

	// targetconfig informer will be added here, the informer needs to have access to the Resolver type
	// which may mean that a pointer to the target collection might be introduced as a dependency to the client
	// which is the collection used that will be used by the informer and the resolver.
```

# Unresolved Questions

- Similar groupings for things like aws credentials can be put under a single key, for example `awsConfig`
