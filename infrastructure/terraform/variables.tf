variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "lambda_function_name" {
  description = "Lambda function name"
  type        = string
}

variable "lambda_role_name" {
  description = "IAM Role name for Lambda function"
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch Log Group Name"
  type        = string
}

variable "event_rule_name" {
  description = "EventBridge rule name"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack Webhook URL for notifications"
  type        = string
}
