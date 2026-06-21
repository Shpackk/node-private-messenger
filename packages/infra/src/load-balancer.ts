import { Duration } from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import type * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";
import type { Construct } from "constructs";

export interface MessengerLoadBalancer {
	loadBalancer: elbv2.ApplicationLoadBalancer;
}

interface CreateMessengerLoadBalancerProps {
	appSecurityGroup: ec2.SecurityGroup;
	certificateArn: string;
	container: ecs.ContainerDefinition;
	domainName: string;
	hostedZoneId: string;
	hostedZoneName: string;
	service: ecs.FargateService;
	vpc: ec2.Vpc;
}

export function createMessengerLoadBalancer(
	scope: Construct,
	props: CreateMessengerLoadBalancerProps,
): MessengerLoadBalancer {
	const loadBalancerSecurityGroup = new ec2.SecurityGroup(scope, "LoadBalancerSecurityGroup", {
		vpc: props.vpc,
	});
	const loadBalancer = new elbv2.ApplicationLoadBalancer(scope, "LoadBalancer", {
		vpc: props.vpc,
		internetFacing: true,
		dropInvalidHeaderFields: true,
		securityGroup: loadBalancerSecurityGroup,
	});

	props.appSecurityGroup.addIngressRule(
		loadBalancerSecurityGroup,
		ec2.Port.tcp(3000),
		"ALB HTTPS target traffic",
	);
	loadBalancer.addRedirect({
		sourcePort: 80,
		targetPort: 443,
		targetProtocol: elbv2.ApplicationProtocol.HTTPS,
	});

	const certificate = acm.Certificate.fromCertificateArn(
		scope,
		"Certificate",
		props.certificateArn,
	);
	const listener = loadBalancer.addListener("Https", {
		port: 443,
		protocol: elbv2.ApplicationProtocol.HTTPS,
		certificates: [certificate],
		sslPolicy: elbv2.SslPolicy.RECOMMENDED_TLS,
	});
	listener.addTargets("ApiTargets", {
		port: 3000,
		protocol: elbv2.ApplicationProtocol.HTTPS,
		targets: [
			props.service.loadBalancerTarget({
				containerName: props.container.containerName,
				containerPort: 3000,
			}),
		],
		healthCheck: {
			enabled: true,
			path: "/health/ready",
			protocol: elbv2.Protocol.HTTPS,
			healthyHttpCodes: "200",
		},
		deregistrationDelay: Duration.seconds(30),
	});

	const zone = route53.HostedZone.fromHostedZoneAttributes(scope, "Zone", {
		hostedZoneId: props.hostedZoneId,
		zoneName: props.hostedZoneName,
	});
	new route53.ARecord(scope, "Alias", {
		zone,
		recordName: props.domainName,
		target: route53.RecordTarget.fromAlias(new route53Targets.LoadBalancerTarget(loadBalancer)),
	});

	return { loadBalancer };
}
