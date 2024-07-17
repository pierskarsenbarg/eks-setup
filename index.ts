import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const ownerTag = "piers";

const awsConfig = new pulumi.Config("aws");
const region: aws.Region = "eu-west-1";

const stackName = pulumi.getStack()

const networkingStackReference = new pulumi.StackReference(`stark-tech/aws-training-module-02-networking/${stackName}`);
const vpcId = networkingStackReference.getOutput("vpcId");
const publicSubnetIds = networkingStackReference.getOutput("publicSubnetIds");
const privateSubnetIds = networkingStackReference.getOutput("privateSubnetIds");

const controlPlaneSg = new aws.ec2.SecurityGroup("controlPlaneSg", {
    vpcId: vpcId,
});


