# Security Hub Exposure Checker - Terraform Configuration

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# Variables
variable "sns_topic_arn" {
  description = "SNS Topic ARN for notifications"
  type        = string
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Lambda function code archive
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_deployment.zip"
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_execution_role" {
  name = "SecurityHubExposureCheckerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "SecurityHubExposureCheckerRole"
    Purpose     = "Security Hub Exposure Checker"
    Environment = "production"
  }
}

# IAM Policy for Lambda
resource "aws_iam_role_policy" "lambda_policy" {
  name = "SecurityHubExposureCheckerPolicy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/SecurityHubExposureChecker:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "rds:DescribeDBInstances",
          "lambda:GetFunctionUrlConfig",
          "eks:DescribeCluster",
          "ecs:DescribeServices"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.sns_topic_arn
      }
    ]
  })
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/SecurityHubExposureChecker"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "SecurityHubExposureChecker-Logs"
    Purpose     = "Security Hub Exposure Checker"
    Environment = "production"
  }
}

# Lambda Function
resource "aws_lambda_function" "exposure_checker" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "SecurityHubExposureChecker"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.9"
  timeout         = var.lambda_timeout
  memory_size     = var.lambda_memory_size
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = var.sns_topic_arn
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda_policy,
    aws_cloudwatch_log_group.lambda_logs
  ]

  tags = {
    Name        = "SecurityHubExposureChecker"
    Purpose     = "Security Hub Exposure Checker"
    Environment = "production"
  }
}

# EventBridge Rule
resource "aws_cloudwatch_event_rule" "security_hub_exposure_rule" {
  name        = "SecurityHubExposureFindingRule"
  description = "Trigger Lambda when Security Hub Exposure Findings are detected"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Type = [
          ["Exposure"]
        ]
      }
    }
  })

  tags = {
    Name        = "SecurityHubExposureFindingRule"
    Purpose     = "Security Hub Exposure Checker"
    Environment = "production"
  }
}

# EventBridge Target
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.security_hub_exposure_rule.name
  target_id = "ExposureCheckerTarget"
  arn       = aws_lambda_function.exposure_checker.arn
}

# Lambda Permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.exposure_checker.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_exposure_rule.arn
}

# Outputs
output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.exposure_checker.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.exposure_checker.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.security_hub_exposure_rule.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.security_hub_exposure_rule.arn
}

output "iam_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_execution_role.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}