
###AWS_System_Manager_SGC_Organization_Role_Policy###
data "aws_iam_policy_document" "sgc_organization_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::082241233631:user/snow_sgc_connector"]
    }

    actions = ["sts:AssumeRole"]
  }
}
