#!/bin/bash

# Fail on error
set -e

# Set AWS region (optional, default is 'us-east-1')
AWS_REGION="us-east-1"
export AWS_REGION

# Terraform Variables (adjust these according to your setup)
SNS_TOPIC_NAME="ExposedKeysNotification"
LAMBDA_FUNCTION_NAME="ExposedKeysHandler"
IAM_ROLE_NAME="LambdaExecutionRole"

# Test if SNS Topic is created
echo "Testing if SNS topic exists..."

SNS_ARN=$(aws sns list-topics --query "Topics[?contains(TopicArn, '${SNS_TOPIC_NAME}')].TopicArn" --output text)

if [ "$SNS_ARN" == "None" ]; then
    echo "ERROR: SNS Topic ${SNS_TOPIC_NAME} not found!"
    exit 1
else
    echo "SNS Topic found: ${SNS_ARN}"
fi

# Test if Lambda Function is created
echo "Testing if Lambda function exists..."

LAMBDA_ARN=$(aws lambda get-function --function-name "${LAMBDA_FUNCTION_NAME}" --query 'Configuration.FunctionArn' --output text)

if [ "$LAMBDA_ARN" == "None" ]; then
    echo "ERROR: Lambda function ${LAMBDA_FUNCTION_NAME} not found!"
    exit 1
else
    echo "Lambda function
