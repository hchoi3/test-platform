
###AWS_System_Manager_SGC_Organization_Role_Policy###
data "aws_iam_policy_document" "sgc_organization_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::082241233635:role/somerolename"]
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
