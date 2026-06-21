import { Duration, RemovalPolicy } from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import type { Construct } from "constructs";

export interface MessengerData {
	dataKey: kms.Key;
	table: dynamodb.Table;
}

export function createMessengerData(scope: Construct): MessengerData {
	const dataKey = new kms.Key(scope, "DataKey", {
		enableKeyRotation: true,
		removalPolicy: RemovalPolicy.RETAIN,
	});

	const table = new dynamodb.Table(scope, "MessengerTable", {
		partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
		sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
		billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
		encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
		encryptionKey: dataKey,
		pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
		timeToLiveAttribute: "ttl",
		deletionProtection: true,
		removalPolicy: RemovalPolicy.RETAIN,
		stream: dynamodb.StreamViewType.OLD_IMAGE,
	});

	table.addGlobalSecondaryIndex({
		indexName: "sender-index",
		partitionKey: { name: "senderPk", type: dynamodb.AttributeType.STRING },
		sortKey: { name: "senderSk", type: dynamodb.AttributeType.STRING },
		projectionType: dynamodb.ProjectionType.ALL,
	});

	addTtlCounterRepair(scope, table);

	table.addGlobalSecondaryIndex({
		indexName: "participant-index",
		partitionKey: { name: "participantPk", type: dynamodb.AttributeType.STRING },
		sortKey: { name: "participantSk", type: dynamodb.AttributeType.STRING },
		projectionType: dynamodb.ProjectionType.KEYS_ONLY,
	});

	return { dataKey, table };
}

function addTtlCounterRepair(scope: Construct, table: dynamodb.Table): void {
	const ttlCounterRepair = new lambda.Function(scope, "TtlCounterRepair", {
		runtime: lambda.Runtime.NODEJS_24_X,
		handler: "index.handler",
		timeout: Duration.seconds(30),
		memorySize: 256,
		environment: { TABLE_NAME: table.tableName },
		code: lambda.Code.fromInline(`
      const { DynamoDBClient, UpdateItemCommand } = require("@aws-sdk/client-dynamodb");
      const client = new DynamoDBClient({});
      exports.handler = async (event) => {
        for (const record of event.Records ?? []) {
          if (record.eventName !== "REMOVE") continue;
          if (record.userIdentity?.type !== "Service") continue;
          if (record.userIdentity?.principalId !== "dynamodb.amazonaws.com") continue;
          const old = record.dynamodb?.OldImage;
          const pk = old?.pk?.S;
          const sk = old?.sk?.S;
          const byteSize = Number(old?.byteSize?.N ?? "0");
          if (!pk?.startsWith("QUEUE#") || !sk?.startsWith("ENVELOPE#")) continue;
          await client.send(new UpdateItemCommand({
            TableName: process.env.TABLE_NAME,
            Key: { pk: { S: pk }, sk: { S: "COUNTER" } },
            UpdateExpression: "ADD envelopeCount :minusOne, byteCount :minusBytes",
            ConditionExpression: "envelopeCount > :zero AND byteCount >= :bytes",
            ExpressionAttributeValues: {
              ":minusOne": { N: "-1" },
              ":minusBytes": { N: String(-byteSize) },
              ":zero": { N: "0" },
              ":bytes": { N: String(byteSize) }
            }
          })).catch((error) => {
            if (error.name !== "ConditionalCheckFailedException") throw error;
          });
        }
      };
    `),
	});

	table.grantReadWriteData(ttlCounterRepair);
	ttlCounterRepair.addEventSource(
		new lambdaEventSources.DynamoEventSource(table, {
			startingPosition: lambda.StartingPosition.LATEST,
			batchSize: 100,
			retryAttempts: 10,
			bisectBatchOnError: true,
		}),
	);
}
