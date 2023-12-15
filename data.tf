
###AWS_System_Manager_SGC_Organization_Role_Policy###
data "aws_iam_policy_document" "sgc_organization_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/somerole"]
    }

    actions = ["sts:AssumeRole"]
  }
}
