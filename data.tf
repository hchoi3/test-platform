data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_vpcs" "current" {}
# locals {
#   vpc_ids_map = {
#     for idx, vpc_id in data.aws_vpcs.current.ids : var.vpc_name[idx] => vpc_id
#   }
# }
data "aws_cloudwatch_log_groups" "ssm" {
  log_group_name_prefix = "/aws/ssm/"
}

data "aws_cloudwatch_log_groups" "vpcflowlogs" {
  log_group_name_prefix = "/aws/vpcflowlogs/"
}

data "archive_file" "origin_request_lambda_source" {
  type        = "zip"
  source_dir  = "${path.module}/../scripts/python"  # Path to the source code directory
  output_path = "${path.module}/../scripts/python_zips/lambda.zip"
}


###CWA Policies###

data "aws_iam_policy_document" "cwa_sqs_queue_policy" {
  version = "2012-10-17"
  statement {
    sid = "First"
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    actions = [
      "sqs:SendMessage",
    ]

    resources = ["arn:aws:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:${var.cloudwatchalerts_sqs_name}"]
    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"

      values = ["arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:${var.cloudwatchalerts_sns_topic_name}",
      ]
    }
  }
}

data "aws_iam_policy_document" "cwa_sns_topic_policy" {
  version = "2008-10-17"
  policy_id = "__default_policy_ID"
  statement {
    sid = "__default_statement_ID"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = ["*"]
    }
    actions = [
        "SNS:GetTopicAttributes",
        "SNS:SetTopicAttributes",
        "SNS:AddPermission",
        "SNS:RemovePermission",
        "SNS:DeleteTopic",
        "SNS:Subscribe",
        "SNS:ListSubscriptionsByTopic",
        "SNS:Publish"
    ]

    resources = ["arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:${var.cloudwatchalerts_sns_topic_name}"]

    condition {
      test = "StringEquals"
      variable = "aws:SourceOwner"

      values = ["${data.aws_caller_identity.current.id}",
      ]
    }
  }
  statement {
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions = ["sns:Publish"]
    resources = ["arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:${var.cloudwatchalerts_sns_topic_name}"]
  }
}

####VPC_flow_log_policies###

data "aws_iam_policy_document" "vpc_flow_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "flow_log_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"]
  }
}

###AWS_System_Manager_S3_Bucket_Policy###
data "aws_iam_policy_document" "aws_ssm_s3_policy" {
  version = "2012-10-17"
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]
 
    resources = ["arn:aws:s3:::${var.aws_ssm_bucket_name}/*",]
}
}

###AWS_System_Manager_SGC_S3_Bucket_Policy###
data "aws_iam_policy_document" "aws_ssm_sgc_s3_policy" {
  version = "2012-10-17"
  statement {
    sid = "AllowAccesstoS3Bucket"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
    principals {
      type        = "AWS"
      identifiers = ["${data.aws_caller_identity.current.account_id}"]
    }

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]
 
    resources = ["arn:aws:s3:::${var.aws_ssm_sgc_bucket_name}", "arn:aws:s3:::${var.aws_ssm_sgc_bucket_name}/*"]
  }
}

###AWS_System_Manager_SGC_Organization_Role_Policy###
data "aws_iam_policy_document" "sgc_organization_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::082241233635:root"]
    }

    actions = ["sts:AssumeRole"]
  }
}


data "aws_iam_policy_document" "sgc_organization_role_policy" {
  statement {
    sid = "ServiceNowUserReadOnlyAccess"
    effect = "Allow"
    actions = [
      "organizations:DescribeOrganization",
      "organizations:ListAccounts",
      "config:ListDiscoveredResources",
      "config:SelectAggregateResourceConfig",
      "config:BatchGetAggregateResourceConfig",
      "config:SelectResourceConfig",
      "config:BatchGetResourceConfig",
      "ec2:DescribeRegions",
      "ec2:DescribeImages",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceTypes",
      "ssm:DescribeInstanceInformation",
      "ssm:ListInventoryEntries",
      "ssm:GetInventory",
      "ssm:SendCommand",
      "s3:GetObject",
      "s3:DeleteObject",
      "tag:GetResources"
    ]

    resources = ["*"]
  }
  statement {
    sid = "SendCommandAccess"
    effect = "Allow"
    actions = [
      "ssm:SendCommand"
    ]

    resources = [
      "arn:aws:ec2:*:*:instance/*",
      "arn:aws:ssm:*:*:document/SG-AWS-RunShellScript",
      "arn:aws:ssm:*:*:document/SG-AWS-RunPowerShellScript"
    ]
  }
  statement {
    sid = "S3BucketAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:DeleteObject"
    ]

    resources = ["arn:aws:s3:::${var.aws_ssm_sgc_bucket_name}/*"]
  }
}

###AWS_System_Manager_ec2_policy###
data "aws_iam_policy_document" "aws_ssm_ec2_policy" {

  statement {
    sid = "PublishSyslogsToCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ssm/${data.aws_caller_identity.current.account_id}/${var.common_tags["environment"]}/ec2/syslogs:*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ssm/${data.aws_caller_identity.current.account_id}/${var.common_tags["environment"]}/ec2/auditlogs:*"
    ]
  }
  statement {
    sid = "PublishSSMResultsToS3"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      "arn:aws:s3:::${var.aws_ssm_bucket_name}/*",
      "arn:aws:s3:::${var.aws_ssm_sgc_bucket_name}/*"
    ]
  }
}

###Security_Group_ABAC_Policy###

data "aws_iam_policy_document" "sg_abac_policy" {
  version = "2012-10-17"
  statement {
    sid = "ReadSG"
    effect = "Allow"

    actions = [
      "ec2:DescribeSecurityGroupRules",
			"ec2:DescribeSecurityGroups",
      "ec2:DescribeTags"
    ]
 
    resources = ["*"]
  }
  statement {
    sid = "AbacSG"
    effect = "Allow"

    actions = [
      "ec2:AuthorizeSecurityGroupIngress", 
      "ec2:RevokeSecurityGroupIngress", 
      "ec2:AuthorizeSecurityGroupEgress", 
      "ec2:RevokeSecurityGroupEgress", 
      "ec2:ModifySecurityGroupRules",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress", 
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress"
    ]

    resources = ["arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:security-group/*"]

    condition {
      test = "StringEquals"
      variable = "aws:PrincipalTag/access-team"

      values = [var.common_tags["access-team"]
      ]
    }
    condition {
      test = "StringEquals"
      variable = "aws:ResourceTag/project"

      values = [var.common_tags["project"]
      ]
    }
    condition {
      test = "StringEquals"
      variable = "aws:ResourceTag/access-team"

      values = [var.common_tags["access-team"]
      ]
    }
  } 
}

###Compliance_Report_Lambda_Role_Policies###
data "aws_iam_policy_document" "lambda_compliance_report_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}


data "aws_iam_policy_document" "lambda_compliance_report_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "config:GetComplianceDetailsByConfigRule",
      "config:StartConfigRulesEvaluation"
    ]

    resources = [
      "arn:aws:s3:::${var.compliance_report_bucket_name}/*",
      "arn:aws:s3:::${var.compliance_report_bucket_name}",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*",
      "arn:aws:config:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:config-rule/*"
    ]
  }
}

###Automation_Role_Policies###
data "aws_iam_policy_document" "automation_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}


data "aws_iam_policy_document" "automation_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "ec2:CreateImage",
      "ec2:CopyImage",
      "ec2:DeregisterImage",
      "ec2:DescribeImages",
      "ec2:DeleteSnapshot",
      "ec2:StartInstances",
      "ec2:RunInstances",
      "ec2:StopInstances",
      "ec2:TerminateInstances",
      "ec2:DescribeInstanceStatus",
      "ec2:CreateTags",
      "ec2:DeleteTags",
      "ec2:DescribeTags",
      "cloudformation:CreateStack",
      "cloudformation:DescribeStackEvents",
      "cloudformation:DescribeStacks",
      "cloudformation:UpdateStack",
      "cloudformation:DeleteStack",
      "ssm:*",
      "sns:Publish",
      "lambda:InvokeFunction"
    ]

    resources = ["*"]
  }
}

###EIC_Endpoint_Assume_Role_Policies###
# data "aws_iam_policy_document" "EIC_assume_role_policy" {
#   statement {
#     effect = "Allow"

#     principals {
#       type        = "AWS"
#       identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
#     }

#     actions = ["sts:AssumeRole"]
#   }
# }

# data "aws_iam_policy_document" "EIC_role_policy" {
#   statement {
#     effect = "Allow"
#     sid = "EC2InstanceConnect"
#     actions = [
#       "ec2-instance-connect:OpenTunnel",
#     ]

#     resources = [module.EC2_EIC.arn]
#   }
#   statement {
#     sid = "SSHPublicKey"
#     effect = "Allow"
#     actions = [
#       "ec2-instance-connect:SendSSHPublicKey",
#     ]
#     resources = ["*"]
#   }
#   statement {
#     sid = "Describe"
#     effect = "Allow"
#     actions = [
#       "ec2:DescribeInstances",
#       "ec2:DescribeInstanceConnectEndpoints"
#     ]
#     resources = ["*"]
# }
# }