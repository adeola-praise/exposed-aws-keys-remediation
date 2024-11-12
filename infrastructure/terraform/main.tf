# main.tf

provider "aws" {
  region = var.region
}

# SNS Topic
resource "aws_sns_topic" "alert_topic" {
  name = var.sns_topic_name
}

# Lambda Execution Role
resource "aws_iam_role" "lambda_role" {
  name               = var.lambda_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for Lambda
resource "aws_iam_policy" "lambda_policy" {
  name        = "LambdaExecutionPolicy"
  description = "Policy for Lambda to access IAM, SNS, and CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "iam:GetAccessKeyLastUsed",
          "iam:UpdateAccessKey"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "logs:FilterLogEvents",
          "logs:GetLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:*:*:log-group:/aws/cloudtrail:*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:*:*:log-group:/aws/lambda/*"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:${var.region}:${var.account_id}:${aws_sns_topic.alert_topic.name}"
      }
    ]
  })
}

# Attach the IAM Policy to the Lambda Execution Role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  policy_arn = aws_iam_policy.lambda_policy.arn
  role       = aws_iam_role.lambda_role.name
}

# Lambda Function
resource "aws_lambda_function" "lambda" {
  function_name = var.lambda_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
  timeout       = 30
  memory_size   = 128

  # Path to your deployment package (zip file)
  filename      = "path_to_your_lambda_package.zip"
  source_code_hash = filebase64sha256("path_to_your_lambda_package.zip")
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name = var.log_group_name
}

# EventBridge Rule
resource "aws_cloudwatch_event_rule" "event_rule" {
  name        = var.event_rule_name
  description = "EventBridge rule to trigger Lambda on access key usage"
  event_pattern = jsonencode({
    "source": [
      "aws.iam"
    ],
    "detail-type": [
      "AWS API Call via CloudTrail"
    ],
    "detail": {
      "eventSource": [
        "iam.amazonaws.com"
      ],
      "eventName": [
        "GetAccessKeyLastUsed",
        "UpdateAccessKey"
      ]
    }
  })
}

# EventBridge Target for Lambda Function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.event_rule.name
  target_id = "lambda-target"
  arn       = aws_lambda_function.lambda.arn
}

# Lambda Permission to be invoked by EventBridge
resource "aws_lambda_permission" "eventbridge_permission" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.event_rule.arn
}
