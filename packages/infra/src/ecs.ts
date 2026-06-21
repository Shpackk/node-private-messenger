import { join } from "node:path";
import { Duration, RemovalPolicy, type Stack } from "aws-cdk-lib";
import type * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecrassets from "aws-cdk-lib/aws-ecr-assets";
import * as ecs from "aws-cdk-lib/aws-ecs";
import type * as elasticache from "aws-cdk-lib/aws-elasticache";
import * as iam from "aws-cdk-lib/aws-iam";
import type * as kms from "aws-cdk-lib/aws-kms";
import * as logs from "aws-cdk-lib/aws-logs";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";

export interface MessengerService {
	cluster: ecs.Cluster;
	container: ecs.ContainerDefinition;
	deploymentAlarmName: string;
	service: ecs.FargateService;
}

interface CreateMessengerServiceProps {
	apnsPlatformArn?: string;
	appSecurityGroup: ec2.SecurityGroup;
	dataKey: kms.Key;
	domainName: string;
	fcmPlatformArn?: string;
	internalTlsSecretArn: string;
	redis: elasticache.CfnReplicationGroup;
	redisSecret: secretsmanager.Secret;
	table: dynamodb.Table;
	vpc: ec2.Vpc;
}

export function createMessengerService(
	stack: Stack,
	props: CreateMessengerServiceProps,
): MessengerService {
	const jwtSecret = new secretsmanager.Secret(stack, "JwtSecret", {
		generateSecretString: {
			excludePunctuation: true,
			passwordLength: 64,
		},
		encryptionKey: props.dataKey,
	});
	const tlsSecret = secretsmanager.Secret.fromSecretCompleteArn(
		stack,
		"InternalTlsSecret",
		props.internalTlsSecretArn,
	);

	const cluster = new ecs.Cluster(stack, "Cluster", {
		vpc: props.vpc,
		containerInsightsV2: ecs.ContainerInsights.ENABLED,
	});
	const task = new ecs.FargateTaskDefinition(stack, "Task", {
		cpu: 512,
		memoryLimitMiB: 1024,
		runtimePlatform: {
			cpuArchitecture: ecs.CpuArchitecture.ARM64,
			operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
		},
	});
	props.table.grantReadWriteData(task.taskRole);
	props.redisSecret.grantRead(task.taskRole);
	jwtSecret.grantRead(task.taskRole);
	tlsSecret.grantRead(task.taskRole);
	task.taskRole.addToPrincipalPolicy(
		new iam.PolicyStatement({
			actions: ["sns:CreatePlatformEndpoint", "sns:Publish", "sns:SetEndpointAttributes"],
			resources: ["*"],
		}),
	);

	const image = new ecrassets.DockerImageAsset(stack, "ApiImage", {
		directory: join(import.meta.dirname, "../../.."),
		platform: ecrassets.Platform.LINUX_ARM64,
	});
	const logGroup = new logs.LogGroup(stack, "ApiLogs", {
		retention: logs.RetentionDays.ONE_WEEK,
		encryptionKey: props.dataKey,
		removalPolicy: RemovalPolicy.DESTROY,
	});
	const container = task.addContainer("Api", {
		image: ecs.ContainerImage.fromDockerImageAsset(image),
		logging: ecs.LogDrivers.awsLogs({ logGroup, streamPrefix: "api" }),
		environment: {
			NODE_ENV: "production",
			PORT: "3000",
			AWS_REGION: stack.region,
			DYNAMODB_TABLE: props.table.tableName,
			REDIS_HOST: props.redis.attrPrimaryEndPointAddress,
			REDIS_PORT: props.redis.attrPrimaryEndPointPort,
			PUBLIC_BASE_URL: `https://${props.domainName}`,
			...(props.apnsPlatformArn ? { SNS_APNS_PLATFORM_ARN: props.apnsPlatformArn } : {}),
			...(props.fcmPlatformArn ? { SNS_FCM_PLATFORM_ARN: props.fcmPlatformArn } : {}),
		},
		secrets: {
			JWT_SECRET_BASE64: ecs.Secret.fromSecretsManager(jwtSecret),
			REDIS_AUTH_TOKEN: ecs.Secret.fromSecretsManager(props.redisSecret),
			TLS_CERT_PEM: ecs.Secret.fromSecretsManager(tlsSecret, "certificate"),
			TLS_KEY_PEM: ecs.Secret.fromSecretsManager(tlsSecret, "privateKey"),
		},
		healthCheck: {
			command: [
				"CMD-SHELL",
				"node -e \"process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';fetch('https://localhost:3000/health/live').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))\"",
			],
			interval: Duration.seconds(30),
			timeout: Duration.seconds(5),
			retries: 3,
			startPeriod: Duration.seconds(30),
		},
	});
	container.addPortMappings({ containerPort: 3000, protocol: ecs.Protocol.TCP });

	const service = new ecs.FargateService(stack, "Service", {
		cluster,
		taskDefinition: task,
		desiredCount: 2,
		assignPublicIp: false,
		securityGroups: [props.appSecurityGroup],
		vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
		circuitBreaker: { rollback: true },
		minHealthyPercent: 100,
		maxHealthyPercent: 200,
	});
	const deploymentAlarmName = `${stack.stackName}-ApiUnhealthyAlarm`;
	service.enableDeploymentAlarms([deploymentAlarmName], {
		behavior: ecs.AlarmBehavior.ROLLBACK_ON_ALARM,
	});

	const scaling = service.autoScaleTaskCount({ minCapacity: 2, maxCapacity: 8 });
	scaling.scaleOnCpuUtilization("CpuScaling", { targetUtilizationPercent: 60 });
	scaling.scaleOnMemoryUtilization("MemoryScaling", { targetUtilizationPercent: 70 });

	return { cluster, container, deploymentAlarmName, service };
}
