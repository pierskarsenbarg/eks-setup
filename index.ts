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
}, {
    aliases: ["urn:pulumi:dev::aws-training-module-02-cluster::pulumi:providers:aws::default_6_32_0"]
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

const cluster = new aws.eks.Cluster("eks-from-scratch", {
    name: clusterName,
    roleArn: eksClusterRole.arn,
    vpcConfig: {
        subnetIds: pulumi.output(allSubnetIds),
        endpointPublicAccess: true,
        endpointPrivateAccess: true,
        securityGroupIds: [controlPlaneSg.id],
    },
    encryptionConfig: {
        provider: {
            keyArn: kmsKey.arn,
        },
        resources: ["secrets"],
    },
    accessConfig: {
        authenticationMode: "API",
        bootstrapClusterCreatorAdminPermissions: true
    },
    version: "1.30",
});

const nodeGroupRole = new aws.iam.Role("nodeRole", {
    assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal(
        aws.iam.Principals.Ec2Principal
    ),
    managedPolicyArns: [
        aws.iam.ManagedPolicy.AmazonEKS_CNI_Policy,
        aws.iam.ManagedPolicy.AmazonEC2ContainerRegistryReadOnly,
        aws.iam.ManagedPolicy.AmazonEKSWorkerNodePolicy,
        aws.iam.ManagedPolicy.AmazonSSMManagedInstanceCore,
    ],
});

const nodeGroupv130 = new aws.eks.NodeGroup("nodeGroup-v130", {
    clusterName: cluster.name,
    nodeRoleArn: nodeGroupRole.arn,
    subnetIds: pulumi.output(allSubnetIds),
    scalingConfig: {
        desiredSize: 3,
        maxSize: 10,
        minSize: 3,
    },
    version: "1.30",
    labels: {
        version: "v1.30",
    },
});

const eksPodIdentityAgent = new aws.eks.Addon("eksPodIdentityAddon", {
    addonName: "eks-pod-identity-agent",
    clusterName: cluster.name,
    addonVersion: "v1.3.0-eksbuild.1",
});

const vpcCniAddon = new aws.eks.Addon("vpcCniAddon", {
    addonName: "vpc-cni",
    clusterName: cluster.name,
    addonVersion: "v1.18.1-eksbuild.3",
});

const coreDnsAddon = new aws.eks.Addon("coreDns", {
    addonName: "coredns",
    clusterName: cluster.name,
    addonVersion: "v1.11.1-eksbuild.9", 
    resolveConflictsOnCreate: "OVERWRITE",
    resolveConflictsOnUpdate: "OVERWRITE",
    configurationValues: JSON.stringify({"autoScaling": {"enabled": true, "minReplicas": 2, "maxReplicas": 10 } }),
});

const podIdentityRole = new aws.iam.Role("podIdentityRole", {
    assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Principal: {
                    Service: "pods.eks.amazonaws.com",
                },
                Effect: "Allow",
                Action: ["sts:AssumeRole", "sts:TagSession"],
            },
        ],
    }),
});