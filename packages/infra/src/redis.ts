import type * as ec2 from "aws-cdk-lib/aws-ec2";
import * as elasticache from "aws-cdk-lib/aws-elasticache";
import type * as kms from "aws-cdk-lib/aws-kms";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import type { Construct } from "constructs";

export interface MessengerRedis {
	redis: elasticache.CfnReplicationGroup;
	redisSecret: secretsmanager.Secret;
}

interface CreateMessengerRedisProps {
	dataKey: kms.Key;
	redisSecurityGroup: ec2.SecurityGroup;
	vpc: ec2.Vpc;
}

export function createMessengerRedis(
	scope: Construct,
	props: CreateMessengerRedisProps,
): MessengerRedis {
	const redisSecret = new secretsmanager.Secret(scope, "RedisAuthToken", {
		generateSecretString: {
			excludePunctuation: true,
			passwordLength: 64,
		},
		encryptionKey: props.dataKey,
	});

	const subnetGroup = new elasticache.CfnSubnetGroup(scope, "RedisSubnetGroup", {
		description: "Private messenger Redis subnets",
		subnetIds: props.vpc.isolatedSubnets.map((subnet) => subnet.subnetId),
	});

	const redis = new elasticache.CfnReplicationGroup(scope, "Redis", {
		replicationGroupDescription: "Private messenger ephemeral routing",
		engine: "redis",
		cacheNodeType: "cache.t4g.micro",
		numCacheClusters: 2,
		automaticFailoverEnabled: true,
		multiAzEnabled: true,
		atRestEncryptionEnabled: true,
		transitEncryptionEnabled: true,
		authToken: redisSecret.secretValue.unsafeUnwrap(),
		cacheSubnetGroupName: subnetGroup.ref,
		securityGroupIds: [props.redisSecurityGroup.securityGroupId],
	});
	redis.addDependency(subnetGroup);

	return { redis, redisSecret };
}
