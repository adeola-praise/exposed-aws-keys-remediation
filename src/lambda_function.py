import boto3
import json
import datetime
import logging
import requests  # Ensure the requests library is in your Lambda environment
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
iam_client = boto3.client('iam')
logs_client = boto3.client('logs')

# Specify your Slack Webhook URL
SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/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'  # Replace with your Slack Webhook URL

def lambda_handler(event, context):
    try:
        logger.info("Processing event: %s", json.dumps(event))
        
        # Extract access key from Health event
        try:
            affected_entities = event['detail']['affectedEntities']
            access_key_id = next(
                (entity['entityValue'] for entity in affected_entities if 'entityValue' in entity),
                None
            )
            if not access_key_id:
                raise ValueError("Access key not found in event")

            logger.info("Extracted access key ID: %s", access_key_id)

        except Exception as e:
            logger.error("Failed to extract access key: %s", str(e))
            return {'statusCode': 400, 'body': 'Access key extraction failed'}
        
        # Suspend the exposed access key
        suspend_access_key_result = suspend_access_key(access_key_id)
        
        # Gather logs
        logs_result = gather_key_usage_logs(access_key_id)

        # Send notification to Slack
        send_slack_notification(access_key_id, suspend_access_key_result, logs_result)
        
        return {
            'statusCode': 200,
            'body': {'accessKeySuspension': suspend_access_key_result, 'logAnalysis': logs_result}
        }

    except Exception as e:
        logger.error("Error processing event: %s", str(e))
        raise

def suspend_access_key(access_key_id):
    try:
        response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
        username = response['UserName']
        
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        
        return {
            'status': 'success',
            'message': f'Successfully suspended access key {access_key_id}',
            'timestamp': datetime.datetime.now().isoformat(),
            'username': username
        }
    except ClientError as e:
        logger.error("Failed to suspend access key: %s", str(e))
        return {
            'status': 'error',
            'message': f'Failed to suspend access key: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }

def gather_key_usage_logs(access_key_id):
    try:
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(hours=24)
        
        response = logs_client.filter_log_events(
            logGroupName='/aws/cloudtrail',
            startTime=int(start_time.timestamp() * 1000),
            endTime=int(end_time.timestamp() * 1000),
            filterPattern=access_key_id,
            limit=1000
        )
        
        log_events = response.get('events', [])
        suspicious_activities = analyze_logs(log_events)
        
        return {
            'status': 'success',
            'message': 'Successfully gathered logs',
            'timeRange': {'start': start_time.isoformat(), 'end': end_time.isoformat()},
            'eventsFound': len(log_events),
            'suspiciousActivities': suspicious_activities
        }
        
    except ClientError as e:
        logger.error("Failed to gather logs: %s", str(e))
        return {'status': 'error', 'message': str(e)}

def analyze_logs(log_events):
    suspicious_activities = []
    suspicious_patterns = {
        'high_volume': 100,
        'sensitive_services': ['iam', 'kms', 'secretsmanager'],
        'suspicious_regions': ['ap-east-1', 'me-south-1']
    }
    
    if len(log_events) > suspicious_patterns['high_volume']:
        suspicious_activities.append({
            'type': 'high_volume',
            'description': f'High volume of requests: {len(log_events)} events in 24 hours',
            'severity': 'HIGH'
        })
    
    for event in log_events:
        try:
            event_data = json.loads(event['message'])
            event_service = event_data.get('eventSource', '').split('.')[0]
            if event_service in suspicious_patterns['sensitive_services']:
                suspicious_activities.append({
                    'type': 'sensitive_service_access',
                    'description': f'Access to sensitive service: {event_service}',
                    'eventId': event_data.get('eventID'),
                    'timestamp': event_data.get('eventTime'),
                    'severity': 'MEDIUM'
                })
            
            event_region = event_data.get('awsRegion')
            if event_region in suspicious_patterns['suspicious_regions']:
                suspicious_activities.append({
                    'type': 'unusual_region',
                    'description': f'Activity in unusual region: {event_region}',
                    'eventId': event_data.get('eventID'),
                    'timestamp': event_data.get('eventTime'),
                    'severity': 'LOW'
                })
                
        except json.JSONDecodeError:
            logger.warning("Could not parse log event: %s", event['message'])
            continue
    
    return suspicious_activities

def send_slack_notification(access_key_id, suspend_result, logs_result):
    try:
        message = (
            f"*Exposed AWS Access Key Detected and Suspended*\n\n"
            f"*Access Key ID:* {access_key_id}\n"
            f"*Suspension Status:* {suspend_result['status']}\n"
            f"*User Associated:* {suspend_result.get('username', 'N/A')}\n"
            f"*Timestamp of Suspension:* {suspend_result.get('timestamp', 'N/A')}\n\n"
            f"*Log Summary:*\n"
            f"*Time Range:* {logs_result.get('timeRange', {}).get('start', 'N/A')} - {logs_result.get('timeRange', {}).get('end', 'N/A')}\n"
            f"*Events Found:* {logs_result.get('eventsFound', 'N/A')}\n"
            f"*Suspicious Activities:* {json.dumps(logs_result.get('suspiciousActivities', []), indent=2)}"
        )
        
        slack_data = {'text': message}
        response = requests.post(SLACK_WEBHOOK_URL, json=slack_data)
        
        if response.status_code != 200:
            raise ValueError(f"Slack returned an error {response.status_code}")
        
        logger.info("Successfully sent Slack notification for access key: %s", access_key_id)
        
    except Exception as e:
        logger.error("Failed to send Slack notification: %s", str(e))
