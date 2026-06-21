import * as ec2 from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

export interface MessengerNetwork {
	vpc: ec2.Vpc;
	appSecurityGroup: ec2.SecurityGroup;
	redisSecurityGroup: ec2.SecurityGroup;
}

export function createMessengerNetwork(scope: Construct): MessengerNetwork {
	const vpc = new ec2.Vpc(scope, "Vpc", {
		maxAzs: 2,
		natGateways: 1,
		subnetConfiguration: [
			{ name: "public", subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
			{
				name: "application",
				subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
				cidrMask: 24,
			},
			{ name: "data", subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
		],
	});

	vpc.addGatewayEndpoint("DynamoEndpoint", {
		service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
	});

	const appSecurityGroup = new ec2.SecurityGroup(scope, "AppSecurityGroup", { vpc });
	const redisSecurityGroup = new ec2.SecurityGroup(scope, "RedisSecurityGroup", { vpc });
	redisSecurityGroup.addIngressRule(appSecurityGroup, ec2.Port.tcp(6379), "ECS to Redis");

	return { vpc, appSecurityGroup, redisSecurityGroup };
}
