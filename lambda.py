import json
import boto3
import os
from datetime import datetime

def lambda_handler(event, context):
    sns = boto3.client('sns')
    
    # EventBridgeから受信したSecurity Hub通知を解析
    detail = event.get('detail', {})
    findings = detail.get('findings', [])
    
    if not findings:
        return {
            'statusCode': 200,
            'body': json.dumps('No findings to process')
        }
    
    # メール本文を作成
    for finding in findings:
        # 必要な情報を抽出
        region = finding.get('Region', 'Unknown')
        account_id = finding.get('AwsAccountId', 'Unknown')
        account_name = get_account_name(account_id)
        resource_id = finding.get('Resources', [{}])[0].get('Id', 'Unknown')
        resource_type = finding.get('Resources', [{}])[0].get('Type', 'Unknown')
        title = finding.get('Title', 'Unknown')
        severity = finding.get('Severity', {}).get('Label', 'Unknown')
        description = finding.get('Description', 'No description available')
        
        # Teams向けのメッセージを構築
        teams_message = {
            "version": "1.0",
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.3",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"🚨 Security Hub Alert - {severity}",
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": "Attention" if severity in ["HIGH", "CRITICAL"] else "Warning"
                            },
                            {
                                "type": "TextBlock",
                                "text": title,
                                "weight": "Bolder",
                                "wrap": True
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "リージョン名", "value": region},
                                    {"title": "アカウント名", "value": account_name},
                                    {"title": "アカウントID", "value": account_id},
                                    {"title": "リソースID", "value": resource_id},
                                    {"title": "リソース名", "value": resource_type},
                                    {"title": "影響", "value": severity},
                                    {"title": "検出時刻", "value": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                                ]
                            },
                            {
                                "type": "TextBlock",
                                "text": f"**説明:** {description}",
                                "wrap": True
                            }
                        ]
                    }
                }
            ]
        }
        
        # SNSトピックにメッセージを送信
        try:
            response = sns.publish(
                TopicArn=os.environ['SNS_TOPIC_ARN'],
                Message=json.dumps(teams_message),
                Subject=f"Security Hub Alert - {severity} - {title}"
            )
            print(f"Message sent successfully: {response['MessageId']}")
        except Exception as e:
            print(f"Error sending message: {str(e)}")
            raise
    
    return {
        'statusCode': 200,
        'body': json.dumps('Successfully processed Security Hub findings')
    }

def get_account_name(account_id):
    """アカウントIDからアカウント名を取得（必要に応じてカスタマイズ）"""
    # アカウントIDとアカウント名のマッピング
    account_mapping = {
        # 実際のアカウントIDとアカウント名に置き換えてください
        '123456789012': 'Production Account',
        '123456789013': 'Development Account',
        '123456789014': 'Staging Account'
    }
    
    return account_mapping.get(account_id, f'Account-{account_id}')