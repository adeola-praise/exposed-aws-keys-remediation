import boto3
import json
import datetime
import logging
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
sns_client = boto3.client('sns')
iam_client = boto3.client('iam')
logs_client = boto3.client('logs')

# Specify the ARN of your SNS topic
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:010526243966:ExposedKeysNotification'

def lambda_handler(event, context):
    """
    Lambda function to handle exposed AWS access keys
    - Suspends the exposed access key
    - Gathers logs for the past 24 hours
    - Returns summary of actions taken
    """
    try:
        logger.info("Processing event: %s", json.dumps(event))
        
        # Extract the access key from the Health event
        try:
            affected_entities = event['detail']['affectedEntities']
            logger.info("Affected entities: %s", json.dumps(affected_entities))  # Log affected entities for debugging
            access_key_id = next(entity['entityValue'] 
                       for entity in affected_entities 
                       if entity['entityType'] == 'ACCESS_KEY')
            logger.info("Extracted access key ID: %s", access_key_id)  # Log the access key ID for debugging
        except (KeyError, StopIteration) as e:
            logger.error("Failed to extract access key from event: %s", str(e))
            return {
                'statusCode': 400,
                'body': 'Failed to extract access key from event'
            }


        # Step 1: Suspend the exposed access key
        suspend_access_key_result = suspend_access_key(access_key_id)
        
        # Step 2: Gather logs
        logs_result = gather_key_usage_logs(access_key_id)

        # Step 3: Send notification via SNS
        send_sns_notification(access_key_id, suspend_access_key_result, logs_result)
        
        # Prepare and return response
        response = {
            'statusCode': 200,
            'body': {
                'accessKeySuspension': suspend_access_key_result,
                'logAnalysis': logs_result
            }
        }
        
        logger.info("Successfully processed exposed key event: %s", json.dumps(response))
        return response
        
    except Exception as e:
        logger.error("Error processing event: %s", str(e))
        raise

def suspend_access_key(access_key_id):
    """
    Suspends the specified IAM access key
    """
    
    try:
        # First, find the username associated with the access key
        response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
        username = response['UserName']
        
        # Suspend the access key
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        
        logger.info("Successfully suspended access key: %s", access_key_id)
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
    """
    Gathers CloudWatch logs for the specified access key for the past 24 hours
    """
    
    try:
        # Calculate time range (last 24 hours)
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(hours=24)
        
        # Convert to milliseconds since epoch
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)
        
        # Get logs from CloudTrail log group
        response = logs_client.filter_log_events(
            logGroupName='/aws/cloudtrail',
            startTime=start_time_ms,
            endTime=end_time_ms,
            filterPattern=f'{access_key_id}',
            limit=1000  # Adjust based on your needs
        )
        
        # Process and analyze the logs
        log_events = response.get('events', [])
        suspicious_activities = analyze_logs(log_events)
        
        logger.info("Successfully gathered logs for key: %s", access_key_id)
        return {
            'status': 'success',
            'message': 'Successfully gathered logs',
            'timestamp': datetime.datetime.now().isoformat(),
            'timeRange': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'eventsFound': len(log_events),
            'suspiciousActivities': suspicious_activities
        }
        
    except ClientError as e:
        logger.error("Failed to gather logs: %s", str(e))
        return {
            'status': 'error',
            'message': f'Failed to gather logs: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }

def analyze_logs(log_events):
    """
    Analyzes logs for suspicious activities
    """
    suspicious_activities = []
    
    # Define suspicious patterns
    suspicious_patterns = {
        'high_volume': 100,  # More than 100 requests in 24 hours
        'sensitive_services': ['iam', 'kms', 'secretsmanager'],
        'suspicious_regions': ['ap-east-1', 'me-south-1']  # Uncommon regions
    }
    
    # Analyze for high volume of requests
    if len(log_events) > suspicious_patterns['high_volume']:
        suspicious_activities.append({
            'type': 'high_volume',
            'description': f'High volume of requests: {len(log_events)} events in 24 hours',
            'severity': 'HIGH'
        })
    
    # Analyze each log event
    for event in log_events:
        try:
            event_data = json.loads(event['message'])
            
            # Check for sensitive service access
            event_service = event_data.get('eventSource', '').split('.')[0]
            if event_service in suspicious_patterns['sensitive_services']:
                suspicious_activities.append({
                    'type': 'sensitive_service_access',
                    'description': f'Access to sensitive service: {event_service}',
                    'eventId': event_data.get('eventID'),
                    'timestamp': event_data.get('eventTime'),
                    'severity': 'MEDIUM'
                })
            
            # Check for unusual regions
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

def send_sns_notification(access_key_id, suspend_result, logs_result):
    """
    Sends an SNS notification with the summary of actions taken on the exposed key.
    """
    try:
        # Format the message
        message = (
            f"Exposed AWS Access Key Detected and Suspended\n\n"
            f"Access Key ID: {access_key_id}\n"
            f"Suspension Status: {suspend_result['status']}\n"
            f"User Associated: {suspend_result.get('username', 'N/A')}\n"
            f"Timestamp of Suspension: {suspend_result.get('timestamp', 'N/A')}\n\n"
            f"Log Summary:\n"
            f"Time Range: {logs_result.get('timeRange', {}).get('start', 'N/A')} - {logs_result.get('timeRange', {}).get('end', 'N/A')}\n"
            f"Events Found: {logs_result.get('eventsFound', 'N/A')}\n"
            f"Suspicious Activities: {json.dumps(logs_result.get('suspiciousActivities', []), indent=2)}"
        )
        
        # Publish the message to SNS
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Exposed AWS Access Key Suspended",
            Message=message
        )
        
        logger.info("Successfully sent SNS notification for access key: %s", access_key_id)
        
    except ClientError as e:
        logger.error("Failed to send SNS notification: %s", str(e))