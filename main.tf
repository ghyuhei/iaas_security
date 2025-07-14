# AWS Provider Configuration
provider "aws" {
  profile = "yhino.tech.AWSAdministratorAccess"
  region  = "ap-northeast-1"
}

# Security Hub通知用のEventBridgeルール
resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "security-hub-findings"
  description = "Capture Security Hub findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

# EventBridgeルールのターゲット（Lambda関数）
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "SecurityHubLambdaTarget"
  arn       = aws_lambda_function.security_hub_processor.arn
}

# Lambda関数の実行権限
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_hub_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_findings.arn
}

# Lambda関数用のZIPファイル
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "lambda.py"
  output_path = "lambda.zip"
}

# Lambda関数
resource "aws_lambda_function" "security_hub_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "security-hub-processor"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "lambda.lambda_handler"
  runtime         = "python3.9"
  timeout         = 60
  
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  
  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_hub_alerts.arn
    }
  }
}

# SNSトピック
resource "aws_sns_topic" "security_hub_alerts" {
  name = "security-hub-alerts"
}

# AWS Chatbot for Microsoft Teams
resource "aws_chatbot_teams_channel_configuration" "security_hub_teams" {
  configuration_name = "security-hub-teams-notifications"
  channel_id         = local.teams_channel_id
  tenant_id          = local.teams_tenant_id
  team_id            = local.teams_team_id
  
  sns_topic_arns = [aws_sns_topic.security_hub_alerts.arn]
  
  iam_role_arn = aws_iam_role.chatbot_execution_role.arn
  
  logging_level = "INFO"
  
  user_authorization_required = false
}

# ローカル変数
locals {
  teams_channel_id = "your-teams-channel-id"
  teams_tenant_id  = "your-teams-tenant-id"
  teams_team_id    = "your-teams-team-id"
}

# Lambda実行用のIAMロール
resource "aws_iam_role" "lambda_execution_role" {
  name = "security-hub-lambda-execution-role"

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
}

# Lambda実行用のIAMポリシー
resource "aws_iam_role_policy" "lambda_execution_policy" {
  name = "security-hub-lambda-execution-policy"
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
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_hub_alerts.arn
      }
    ]
  })
}

# AWS Chatbot用のIAMロール
resource "aws_iam_role" "chatbot_execution_role" {
  name = "aws-chatbot-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "chatbot.amazonaws.com"
        }
      }
    ]
  })
}

# AWS Chatbot用のIAMポリシー
resource "aws_iam_role_policy" "chatbot_execution_policy" {
  name = "aws-chatbot-execution-policy"
  role = aws_iam_role.chatbot_execution_role.id

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
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:GetTopicAttributes",
          "sns:ListTopics"
        ]
        Resource = "*"
      }
    ]
  })
}