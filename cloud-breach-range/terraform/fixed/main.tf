# The same shop with a control on every link of the chain. Each one stops
# the attack by itself; together they are defence in depth.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ami_id" {
  type        = string
  description = "AMI for the web server."
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "route_table_ids" {
  type = list(string)
}

# --- the web server ---------------------------------------------------------

resource "aws_instance" "shop_web" {
  ami                  = var.ami_id
  instance_type        = "t3.small"
  subnet_id            = var.subnet_id
  iam_instance_profile = aws_iam_instance_profile.shop_web.name
  monitoring           = true
  ebs_optimized        = true

  # Link 2: IMDSv2 only. A token must be requested with PUT and a custom
  # header, which an SSRF through a GET-only feature cannot do. A hop limit of
  # 1 also keeps the token from reaching containers behind the host.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "shop-web" }
}

# --- the role ---------------------------------------------------------------

resource "aws_iam_role" "shop_web" {
  name = "shop-web-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "shop_web" {
  name = "shop-web"
  role = aws_iam_role.shop_web.name
}

# Link 3: least privilege. The server reads its own assets and nothing else.
resource "aws_iam_role_policy" "shop_web" {
  name = "shop-web-role-policy"
  role = aws_iam_role.shop_web.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadShopAssets"
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.assets.arn}/*"
    }]
  })
}

# --- the data ---------------------------------------------------------------

resource "aws_kms_key" "data" {
  description         = "Customer exports"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdmin"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_s3_bucket" "assets" {
  bucket = "acme-shop-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-exports"
}

resource "aws_s3_bucket_public_access_block" "customer_exports" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

# The internal jobs that need the exports reach S3 through this endpoint.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.route_table_ids
}

# Link 4: the data bucket refuses every request that did not come through the
# VPC endpoint, even one signed with valid credentials.
resource "aws_s3_bucket_policy" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyOutsideVpcEndpoint"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.customer_exports.arn, "${aws_s3_bucket.customer_exports.arn}/*"]
      Condition = { StringNotEquals = { "aws:SourceVpce" = aws_vpc_endpoint.s3.id } }
    }]
  })
}

# --- detection and response (link 5) ----------------------------------------

resource "aws_cloudtrail" "main" {
  name                          = "acme-trail"
  s3_bucket_name                = "acme-cloudtrail-logs"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.data.arn

  # Record every read and write of the customer data, not only management calls.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.customer_exports.arn}/"]
    }
  }
}

resource "aws_guardduty_detector" "main" {
  enable = true
}

# When GuardDuty sees instance credentials used outside AWS, revoke the role's sessions.
resource "aws_cloudwatch_event_rule" "credential_exfiltration" {
  name = "instance-credential-exfiltration"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "revoke" {
  rule = aws_cloudwatch_event_rule.credential_exfiltration.name
  arn  = aws_lambda_function.revoke.arn
}

data "archive_file" "revoke" {
  type        = "zip"
  source_file = "${path.module}/revoke/handler.py"
  output_path = "${path.module}/build/revoke.zip"
}

resource "aws_iam_role" "revoke" {
  name = "revoke-instance-sessions"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "revoke" {
  name = "revoke-instance-sessions"
  role = aws_iam_role.revoke.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AttachRevocation", Effect = "Allow", Action = "iam:PutRolePolicy", Resource = aws_iam_role.shop_web.arn },
      { Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:*" },
    ]
  })
}

resource "aws_lambda_function" "revoke" {
  function_name                  = "revoke-instance-sessions"
  role                           = aws_iam_role.revoke.arn
  runtime                        = "python3.12"
  handler                        = "handler.handler"
  filename                       = data.archive_file.revoke.output_path
  source_code_hash               = data.archive_file.revoke.output_base64sha256
  timeout                        = 10
  reserved_concurrent_executions = 2

  environment {
    variables = { ROLE_NAME = aws_iam_role.shop_web.name }
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.revoke.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.credential_exfiltration.arn
}
