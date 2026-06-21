import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import type { Construct } from "constructs";
import { createMessengerData } from "./dynamodb.js";
import { createMessengerService } from "./ecs.js";
import { createMessengerLoadBalancer } from "./load-balancer.js";
import { createMessengerNetwork } from "./network.js";
import { createMessengerRedis } from "./redis.js";
import { addMessengerSecurity } from "./security.js";

interface MessengerStackProps extends StackProps {
	certificateArn: string;
	domainName: string;
	hostedZoneId: string;
	hostedZoneName: string;
	internalTlsSecretArn: string;
	apnsPlatformArn?: string;
	fcmPlatformArn?: string;
}

export class MessengerStack extends Stack {
	constructor(scope: Construct, id: string, props: MessengerStackProps) {
		super(scope, id, props);

		const { dataKey, table } = createMessengerData(this);
		const { appSecurityGroup, redisSecurityGroup, vpc } = createMessengerNetwork(this);
		const { redis, redisSecret } = createMessengerRedis(this, {
			dataKey,
			redisSecurityGroup,
			vpc,
		});
		const { container, deploymentAlarmName, service } = createMessengerService(this, {
			appSecurityGroup,
			dataKey,
			domainName: props.domainName,
			internalTlsSecretArn: props.internalTlsSecretArn,
			redis,
			redisSecret,
			table,
			vpc,
			...(props.apnsPlatformArn ? { apnsPlatformArn: props.apnsPlatformArn } : {}),
			...(props.fcmPlatformArn ? { fcmPlatformArn: props.fcmPlatformArn } : {}),
		});
		const { loadBalancer } = createMessengerLoadBalancer(this, {
			appSecurityGroup,
			certificateArn: props.certificateArn,
			container,
			domainName: props.domainName,
			hostedZoneId: props.hostedZoneId,
			hostedZoneName: props.hostedZoneName,
			service,
			vpc,
		});
		addMessengerSecurity(this, {
			dataKey,
			deploymentAlarmName,
			loadBalancer,
			service,
		});

		new CfnOutput(this, "ApiUrl", { value: `https://${props.domainName}` });
		new CfnOutput(this, "TableName", { value: table.tableName });
	}
}
