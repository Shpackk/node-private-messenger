import { App } from "aws-cdk-lib";
import { MessengerStack } from "./messenger-stack.js";

const app = new App();
const certificateArn = app.node.tryGetContext("certificateArn") as string | undefined;
const domainName = app.node.tryGetContext("domainName") as string | undefined;
const hostedZoneId = app.node.tryGetContext("hostedZoneId") as string | undefined;
const hostedZoneName = app.node.tryGetContext("hostedZoneName") as string | undefined;
const internalTlsSecretArn = app.node.tryGetContext("internalTlsSecretArn") as string | undefined;

if (!certificateArn || !domainName || !hostedZoneId || !hostedZoneName || !internalTlsSecretArn) {
	throw new Error(
		"Required CDK context: certificateArn, domainName, hostedZoneId, hostedZoneName, internalTlsSecretArn",
	);
}

new MessengerStack(app, "PrivateMessengerBackend", {
	env: {
		region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
		...(process.env.CDK_DEFAULT_ACCOUNT ? { account: process.env.CDK_DEFAULT_ACCOUNT } : {}),
	},
	certificateArn,
	domainName,
	hostedZoneId,
	hostedZoneName,
	internalTlsSecretArn,
	apnsPlatformArn: app.node.tryGetContext("apnsPlatformArn") as string | undefined,
	fcmPlatformArn: app.node.tryGetContext("fcmPlatformArn") as string | undefined,
});
