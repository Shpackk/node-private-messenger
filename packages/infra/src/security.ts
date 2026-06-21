import * as cloudtrail from "aws-cdk-lib/aws-cloudtrail";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import type * as ecs from "aws-cdk-lib/aws-ecs";
import type * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as guardduty from "aws-cdk-lib/aws-guardduty";
import type * as kms from "aws-cdk-lib/aws-kms";
import * as logs from "aws-cdk-lib/aws-logs";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import type { Construct } from "constructs";

interface AddMessengerSecurityProps {
	dataKey: kms.Key;
	deploymentAlarmName: string;
	loadBalancer: elbv2.ApplicationLoadBalancer;
	service: ecs.FargateService;
}

export function addMessengerSecurity(scope: Construct, props: AddMessengerSecurityProps): void {
	const webAcl = new wafv2.CfnWebACL(scope, "WebAcl", {
		defaultAction: { allow: {} },
		scope: "REGIONAL",
		visibilityConfig: {
			cloudWatchMetricsEnabled: true,
			metricName: "private-messenger-waf",
			sampledRequestsEnabled: false,
		},
		rules: [
			managedRule("CommonRules", "AWSManagedRulesCommonRuleSet", 10),
			managedRule("KnownBadInputs", "AWSManagedRulesKnownBadInputsRuleSet", 20),
			{
				name: "IpRateLimit",
				priority: 30,
				action: { block: {} },
				statement: { rateBasedStatement: { aggregateKeyType: "IP", limit: 2_000 } },
				visibilityConfig: {
					cloudWatchMetricsEnabled: true,
					metricName: "ip-rate-limit",
					sampledRequestsEnabled: false,
				},
			},
		],
	});
	new wafv2.CfnWebACLAssociation(scope, "WebAclAssociation", {
		resourceArn: props.loadBalancer.loadBalancerArn,
		webAclArn: webAcl.attrArn,
	});

	new cloudtrail.Trail(scope, "AuditTrail", {
		encryptionKey: props.dataKey,
		sendToCloudWatchLogs: true,
		cloudWatchLogsRetention: logs.RetentionDays.ONE_MONTH,
		includeGlobalServiceEvents: true,
		isMultiRegionTrail: true,
		enableFileValidation: true,
	});
	new guardduty.CfnDetector(scope, "GuardDuty", { enable: true });

	const unhealthyAlarm = new cloudwatch.Alarm(scope, "ApiUnhealthyAlarm", {
		alarmName: props.deploymentAlarmName,
		metric: props.service.metricCpuUtilization(),
		threshold: 95,
		evaluationPeriods: 3,
		datapointsToAlarm: 3,
	});
	unhealthyAlarm.node.addDependency(props.service);
}

function managedRule(
	name: string,
	ruleName: string,
	priority: number,
): wafv2.CfnWebACL.RuleProperty {
	return {
		name,
		priority,
		overrideAction: { none: {} },
		statement: {
			managedRuleGroupStatement: { vendorName: "AWS", name: ruleName },
		},
		visibilityConfig: {
			cloudWatchMetricsEnabled: true,
			metricName: name,
			sampledRequestsEnabled: false,
		},
	};
}
