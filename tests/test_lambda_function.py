import json
import pytest
from unittest import mock
from lambda_function import lambda_handler

# Sample event for testing
event = {
    'detail': {
        'affectedEntities': [
            {
                'entityType': 'ACCESS_KEY',
                'entityValue': 'AKIAEXAMPLEACCESSKEYID'
            }
        ]
    }
}

# Mock the boto3 client and methods
sns_client = mock.Mock()
iam_client = mock.Mock()
logs_client = mock.Mock()

# Patch the boto3 client calls in your Lambda function
@mock.patch('boto3.client')
def test_lambda_handler(mock_boto_client):
    # Mock responses for SNS, IAM, and CloudWatch logs clients
    mock_boto_client.side_effect = lambda service: {
        'sns': sns_client,
        'iam': iam_client,
        'logs': logs_client
    }[service]

    # Mock the result of IAM methods
    iam_client.get_access_key_last_used.return_value = {
        'UserName': 'test-user'
    }
    iam_client.update_access_key.return_value = {}
    
    # Mock CloudWatch logs response
    logs_client.filter_log_events.return_value = {
        'events': [
            {'message': '{"eventSource":"iam.amazonaws.com","awsRegion":"us-east-1"}'}
        ]
    }

    # Mock SNS publish method
    sns_client.publish.return_value = {}

    # Call the lambda_handler function
    response = lambda_handler(event, {})

    # Assert the lambda handler works as expected
    assert response['statusCode'] == 200
    assert 'accessKeySuspension' in response['body']
    assert 'logAnalysis' in response['body']
    assert sns_client.publish.called  # Ensure the SNS notification was sent
    sns_client.publish.assert_called_once_with(
        TopicArn='arn:aws:sns:us-east-1:010526243966:ExposedKeysNotification',
        Subject="Exposed AWS Access Key Suspended",
        Message=mock.ANY  # You can refine this to match the exact message
    )

    # Ensure IAM update_access_key is called
    iam_client.update_access_key.assert_called_once_with(
        UserName='test-user',
        AccessKeyId='AKIAEXAMPLEACCESSKEYID',
        Status='Inactive'
    )

    # Ensure logs are being fetched
    logs_client.filter_log_events.assert_called_once_with(
        logGroupName='/aws/cloudtrail',
        startTime=mock.ANY,  # Mocked time in the Lambda function
        endTime=mock.ANY,
        filterPattern='AKIAEXAMPLEACCESSKEYID',
        limit=1000
    )

# Run the test with pytest
if __name__ == '__main__':
    pytest.main()
