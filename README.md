# Setting up EKS from scratch

A Pulumi program to help you set up an EKS cluster from scratch.

This will deploy the following:

- VPC with public, private subnets, security group
- EKS cluster
- Node group
- AWS ALB Controller
- Access Entry to allow access to the cluster
- CoreDns, PodIdentity and VpcCni add ons
- Service accounts, namespaces and pods for a hello world app

## Setup

1. Clone this repo and `cd` into it
1. Create a new stack `pulumi stack init dev`
1. Set AWS region: `pulumi config set aws:{region}`
1. Set the AWS IAM role that you want to use to authenticate with the cluster once it's set up: `pulumi config set accessRole {role arn}`
1. Set the name for the `ownerTag` tag that we set (because we are responsible)
