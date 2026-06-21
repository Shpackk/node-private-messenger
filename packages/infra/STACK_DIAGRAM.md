# Private Messenger AWS Stack

```mermaid
flowchart TB
  user["Client apps"] --> dns["Route53 A record<br/>api domain"]
  dns --> waf["AWS WAF<br/>managed rules + IP rate limit"]
  waf --> alb["Application Load Balancer<br/>public HTTPS 443"]
  alb --> ecs["ECS Fargate Service<br/>2-8 private API tasks"]

  subgraph vpc["VPC across 2 Availability Zones"]
    subgraph public["public subnets"]
      alb
    end

    subgraph app["application private subnets"]
      ecs
    end

    subgraph data["isolated data subnets"]
      redis["ElastiCache Redis<br/>Multi-AZ + encrypted"]
    end

    endpoint["DynamoDB Gateway Endpoint"]
  end

  ecs --> endpoint
  endpoint --> table["DynamoDB MessengerTable<br/>TTL + streams + GSIs"]
  table --> stream["DynamoDB Stream<br/>expired item OLD_IMAGE"]
  stream --> repair["Lambda TtlCounterRepair<br/>fix queue counters"]
  repair --> table

  ecs --> redis
  ecs --> secrets["Secrets Manager<br/>JWT, Redis auth, internal TLS"]
  ecs --> sns["SNS<br/>APNs/FCM push"]

  kms["KMS DataKey<br/>rotation enabled"] --> table
  kms --> secrets
  kms --> logs["CloudWatch Logs"]
  kms --> trail["CloudTrail"]

  ecs --> logs
  trail --> logs
  guard["GuardDuty"] -. monitors account .-> trail
  alarm["CloudWatch CPU alarm<br/>deployment rollback trigger"] --> ecs
```

## File Map

- `src/messenger-stack.ts`: top-level wiring and stack outputs.
- `src/dynamodb.ts`: KMS key, DynamoDB table, indexes, TTL counter repair Lambda.
- `src/network.ts`: VPC, subnets, DynamoDB endpoint, security groups.
- `src/redis.ts`: Redis auth secret, subnet group, ElastiCache replication group.
- `src/ecs.ts`: ECS cluster, Fargate task/service, Docker image, secrets, logs, autoscaling.
- `src/load-balancer.ts`: ALB, public TLS listener, target group, Route53 alias record.
- `src/security.ts`: WAF, CloudTrail, GuardDuty, deployment rollback alarm.
