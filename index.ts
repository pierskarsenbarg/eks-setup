import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const ownerTag = "piers";

const stackConfig = new pulumi.Config();
const region: aws.Region = stackConfig.require("awsRegion");

const stackName = pulumi.getStack()

const clusterName = `eks-from-scratch-${ownerTag}`;

const awsProvider = new aws.Provider("provider", {
    region: region,
    defaultTags: {
        tags: {
            owner: ownerTag,
        },
    },
});

pulumi.runtime.registerStackTransformation((args) => {
    if (args.type.startsWith("aws")) {
        return {
            props: args.props,
            opts: pulumi.mergeOptions(args.opts, { provider: awsProvider }),
        };
    }
    return undefined;
});

const networkingStackReference = new pulumi.StackReference(`stark-tech/aws-training-module-02-networking/${stackName}`);
const vpcId = networkingStackReference.getOutput("vpcId");
const publicSubnetIds = networkingStackReference.getOutput("publicSubnetIds");
const privateSubnetIds = networkingStackReference.getOutput("privateSubnetIds");

const controlPlaneSg = new aws.ec2.SecurityGroup("controlPlaneSg", {
    vpcId: vpcId,
});

const eksClusterRole = new aws.iam.Role("eksClusterRole", {
    assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal(
        aws.iam.Principals.EksPrincipal
    ),
});

const eksClusterPolicyAttachment = new aws.iam.RolePolicyAttachment(
    "eksClusterPolicyAttachment",
    {
        role: eksClusterRole,
        policyArn: aws.iam.ManagedPolicy.AmazonEKSClusterPolicy,
    }
);

const kmsKey = new aws.kms.Key("clusterKey");

const allSubnetIds = pulumi
    .all([publicSubnetIds, privateSubnetIds])
    .apply(([publicSubnetIds, privateSubnets]) => {
        return publicSubnetIds.concat(privateSubnets);
    });