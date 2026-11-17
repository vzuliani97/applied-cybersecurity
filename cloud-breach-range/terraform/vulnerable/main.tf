# The shop as it was deployed: every link of the attack chain is open.
# This stack is for reading and scanning only. Do not apply it.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ami_id" {
  type        = string
  description = "AMI for the web server."
}

variable "subnet_id" {
  type = string
}

# --- the web server ---------------------------------------------------------

resource "aws_instance" "shop_web" {
  ami                  = var.ami_id
  instance_type        = "t3.small"
  subnet_id            = var.subnet_id
  iam_instance_profile = aws_iam_instance_profile.shop_web.name

  # Link 2: IMDSv1 is still allowed. Any GET to 169.254.169.254 from the
  # instance, including one an SSRF sends, gets the role's credentials.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
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

# Link 3: the server only reads its own images, but its role can do anything in S3.
resource "aws_iam_role_policy" "shop_web" {
  name = "shop-web-role-policy"
  role = aws_iam_role.shop_web.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "S3FullAccess"
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

# --- the data ---------------------------------------------------------------

resource "aws_s3_bucket" "assets" {
  bucket = "acme-shop-assets"
}

# Link 4: no bucket policy. Valid credentials work from anywhere on the internet.
resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-exports"
}

# Link 5: CloudTrail keeps only management events, so S3 downloads are not
# recorded, and nothing watches for credentials used outside AWS.
resource "aws_cloudtrail" "main" {
  name           = "acme-trail"
  s3_bucket_name = "acme-cloudtrail-logs"
}
