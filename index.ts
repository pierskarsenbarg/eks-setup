import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as tls from "@pulumi/tls";
import * as k8s from "@pulumi/kubernetes";

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

const certs = tls.getCertificateOutput({
    url: cluster.identities[0].oidcs[0].issuer,
});

const oidcProvider = new aws.iam.OpenIdConnectProvider("eksOidcProvider", {
    clientIdLists: ["sts.amazonaws.com"],
    thumbprintLists: [certs.certificates[0].sha1Fingerprint],
    url: cluster.identities[0].oidcs[0].issuer,
});

const getKubeconfig = (
    endpoint: pulumi.Output<string>,
    certData: pulumi.Output<string>,
    clusterName: pulumi.Output<string>
): pulumi.Output<string> => {
    return pulumi
        .all([endpoint, certData, clusterName])
        .apply(([endpoint, certData, clusterName]) => {
            return pulumi.jsonStringify({
                apiVersion: "v1",
                clusters: [
                    {
                        cluster: {
                            "certificate-authority-data": certData,
                            server: endpoint,
                        },
                        name: clusterName,
                    },
                ],
                contexts: [
                    {
                        context: {
                            cluster: clusterName,
                            user: "aws-user",
                        },
                        name: "eks-from-scratch",
                    },
                ],
                "current-context": "eks-from-scratch",
                kind: "Config",
                preferences: {},
                users: [
                    {
                        name: "aws-user",
                        user: {
                            exec: {
                                apiVersion:
                                    "client.authentication.k8s.io/v1beta1",
                                args: [
                                    "--region",
                                    "eu-west-1",
                                    "eks",
                                    "get-token",
                                    "--cluster-name",
                                    clusterName,
                                    "--output",
                                    "json",
                                ],
                                command: "aws",
                            },
                        },
                    },
                ],
            });
        });
};

export const kubeconfig = pulumi.secret(
    getKubeconfig(
        cluster.endpoint,
        cluster.certificateAuthority.data,
        cluster.name
    )
);

const k8sprovider = new k8s.Provider("k8sProvider", {
    kubeconfig: kubeconfig,
}, { dependsOn: cluster });

const albControllerPolicy = new aws.iam.Policy("albControllerPolicy", {
    policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Action: ["iam:CreateServiceLinkedRole"],
                Resource: "*",
                Condition: {
                    StringEquals: {
                        "iam:AWSServiceName":
                            "elasticloadbalancing.amazonaws.com",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: [
                    "ec2:DescribeAccountAttributes",
                    "ec2:DescribeAddresses",
                    "ec2:DescribeAvailabilityZones",
                    "ec2:DescribeInternetGateways",
                    "ec2:DescribeVpcs",
                    "ec2:DescribeVpcPeeringConnections",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeInstances",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DescribeTags",
                    "ec2:GetCoipPoolUsage",
                    "ec2:DescribeCoipPools",
                    "elasticloadbalancing:DescribeLoadBalancers",
                    "elasticloadbalancing:DescribeLoadBalancerAttributes",
                    "elasticloadbalancing:DescribeListeners",
                    "elasticloadbalancing:DescribeListenerCertificates",
                    "elasticloadbalancing:DescribeSSLPolicies",
                    "elasticloadbalancing:DescribeRules",
                    "elasticloadbalancing:DescribeTargetGroups",
                    "elasticloadbalancing:DescribeTargetGroupAttributes",
                    "elasticloadbalancing:DescribeTargetHealth",
                    "elasticloadbalancing:DescribeTags",
                    "elasticloadbalancing:DescribeTrustStores",
                ],
                Resource: "*",
            },
            {
                Effect: "Allow",
                Action: [
                    "cognito-idp:DescribeUserPoolClient",
                    "acm:ListCertificates",
                    "acm:DescribeCertificate",
                    "iam:ListServerCertificates",
                    "iam:GetServerCertificate",
                    "waf-regional:GetWebACL",
                    "waf-regional:GetWebACLForResource",
                    "waf-regional:AssociateWebACL",
                    "waf-regional:DisassociateWebACL",
                    "wafv2:GetWebACL",
                    "wafv2:GetWebACLForResource",
                    "wafv2:AssociateWebACL",
                    "wafv2:DisassociateWebACL",
                    "shield:GetSubscriptionState",
                    "shield:DescribeProtection",
                    "shield:CreateProtection",
                    "shield:DeleteProtection",
                ],
                Resource: "*",
            },
            {
                Effect: "Allow",
                Action: [
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupIngress",
                ],
                Resource: "*",
            },
            {
                Effect: "Allow",
                Action: ["ec2:CreateSecurityGroup"],
                Resource: "*",
            },
            {
                Effect: "Allow",
                Action: ["ec2:CreateTags"],
                Resource: "arn:aws:ec2:*:*:security-group/*",
                Condition: {
                    StringEquals: {
                        "ec2:CreateAction": "CreateSecurityGroup",
                    },
                    Null: {
                        "aws:RequestTag/elbv2.k8s.aws/cluster": "false",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: ["ec2:CreateTags", "ec2:DeleteTags"],
                Resource: "arn:aws:ec2:*:*:security-group/*",
                Condition: {
                    Null: {
                        "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                        "aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: [
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupIngress",
                    "ec2:DeleteSecurityGroup",
                ],
                Resource: "*",
                Condition: {
                    Null: {
                        "aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: [
                    "elasticloadbalancing:CreateLoadBalancer",
                    "elasticloadbalancing:CreateTargetGroup",
                ],
                Resource: "*",
                Condition: {
                    Null: {
                        "aws:RequestTag/elbv2.k8s.aws/cluster": "false",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: [
                    "elasticloadbalancing:CreateListener",
                    "elasticloadbalancing:DeleteListener",
                    "elasticloadbalancing:CreateRule",
                    "elasticloadbalancing:DeleteRule",
                ],
                Resource: "*",
            },
            {
                Effect: "Allow",
                Action: [
                    "elasticloadbalancing:AddTags",
                    "elasticloadbalancing:RemoveTags",
                ],
                Resource: [
                    "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                    "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                    "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
                ],
                Condition: {
                    Null: {
                        "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                        "aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: [
                    "elasticloadbalancing:AddTags",
                    "elasticloadbalancing:RemoveTags",
                ],
                Resource: [
                    "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                    "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                    "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                    "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*",
                ],
            },
            {
                Effect: "Allow",
                Action: [
                    "elasticloadbalancing:ModifyLoadBalancerAttributes",
                    "elasticloadbalancing:SetIpAddressType",
                    "elasticloadbalancing:SetSecurityGroups",
                    "elasticloadbalancing:SetSubnets",
                    "elasticloadbalancing:DeleteLoadBalancer",
                    "elasticloadbalancing:ModifyTargetGroup",
                    "elasticloadbalancing:ModifyTargetGroupAttributes",
                    "elasticloadbalancing:DeleteTargetGroup",
                ],
                Resource: "*",
                Condition: {
                    Null: {
                        "aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: ["elasticloadbalancing:AddTags"],
                Resource: [
                    "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                    "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                    "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
                ],
                Condition: {
                    StringEquals: {
                        "elasticloadbalancing:CreateAction": [
                            "CreateTargetGroup",
                            "CreateLoadBalancer",
                        ],
                    },
                    Null: {
                        "aws:RequestTag/elbv2.k8s.aws/cluster": "false",
                    },
                },
            },
            {
                Effect: "Allow",
                Action: [
                    "elasticloadbalancing:RegisterTargets",
                    "elasticloadbalancing:DeregisterTargets",
                ],
                Resource: "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
            },
            {
                Effect: "Allow",
                Action: [
                    "elasticloadbalancing:SetWebAcl",
                    "elasticloadbalancing:ModifyListener",
                    "elasticloadbalancing:AddListenerCertificates",
                    "elasticloadbalancing:RemoveListenerCertificates",
                    "elasticloadbalancing:ModifyRule",
                ],
                Resource: "*",
            },
        ],
    }),
});

const rpaAlbPolicy = new aws.iam.RolePolicyAttachment("albPolicy", {
    policyArn: albControllerPolicy.arn,
    role: podIdentityRole,
});

const albServiceAccount = new k8s.core.v1.ServiceAccount(
    "albServiceAccount",
    {
        metadata: {
            name: "aws-load-balancer-controller",
            namespace: "kube-system",
        },
    },
    { provider: k8sprovider }
);

const albPodIdentityAssociation = new aws.eks.PodIdentityAssociation(
    "albPodIdentityAssociation",
    {
        clusterName: cluster.name,
        serviceAccount: albServiceAccount.metadata.name,
        roleArn: podIdentityRole.arn,
        namespace: "kube-system",
    }
);

const albHelm = new k8s.helm.v3.Release(
    "albhelm",
    {
        repositoryOpts: {
            repo: "https://aws.github.io/eks-charts",
        },
        chart: "aws-load-balancer-controller",
        namespace: "kube-system",
        values: {
            clusterName: cluster.name,
            serviceAccount: {
                create: false,
                name: "aws-load-balancer-controller",
            },
            region: "eu-west-1",
            vpcId: vpcId,
        },
    },
    { dependsOn: [albPodIdentityAssociation], provider: k8sprovider }
);