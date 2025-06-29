import json
import boto3
import socket
import os
from datetime import datetime

def lambda_handler(event, context):
    """
    Security Hub Exposure Findingを受信し、実際の匿名アクセステストを実行
    """
    print(f"Event received: {json.dumps(event, default=str)}")
    
    try:
        # EventBridgeイベントからfindingsを抽出
        detail = event.get('detail', {})
        findings = detail.get('findings', [])
        
        results = []
        
        for finding in findings:
            # Exposure Findingのみ処理
            if 'Exposure' in finding.get('Type', []):
                result = process_finding(finding)
                results.append(result)
        
        # SNS通知
        if results:
            send_sns_notification(results)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Success',
                'processed_count': len(results),
                'results': results
            }, default=str)
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def process_finding(finding):
    """個別のExposure Findingを処理"""
    
    finding_id = finding.get('Id', '')
    title = finding.get('Title', '')
    severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
    
    result = {
        'finding_id': finding_id,
        'title': title,
        'severity': severity,
        'timestamp': datetime.utcnow().isoformat(),
        'is_accessible': False,
        'test_results': []
    }
    
    # リソースをテスト
    resources = finding.get('Resources', [])
    for resource in resources:
        resource_type = resource.get('Type', '')
        resource_id = resource.get('Id', '')
        
        print(f"Testing {resource_type}: {resource_id}")
        
        is_accessible, details = test_resource(resource_type, resource_id)
        
        result['test_results'].append({
            'resource_type': resource_type,
            'resource_id': resource_id,
            'is_accessible': is_accessible,
            'details': details
        })
        
        if is_accessible:
            result['is_accessible'] = True
    
    return result

def test_resource(resource_type, resource_id):
    """リソースタイプ別のアクセステスト"""
    
    try:
        if resource_type == 'AWS::EC2::Instance':
            return test_ec2_instance(resource_id)
        elif resource_type == 'AWS::RDS::DBInstance':
            return test_rds_instance(resource_id)
        elif resource_type == 'AWS::S3::Bucket':
            return test_s3_bucket(resource_id)
        elif resource_type == 'AWS::Lambda::Function':
            return test_lambda_function(resource_id)
        elif resource_type == 'AWS::ECS::Service':
            return test_ecs_service(resource_id)
        elif resource_type == 'AWS::EKS::Cluster':
            return test_eks_cluster(resource_id)
        elif resource_type == 'AWS::DynamoDB::Table':
            return test_dynamodb_table(resource_id)
        elif resource_type == 'AWS::IAM::User':
            return test_iam_user(resource_id)
        else:
            return False, {'error': f'Unsupported resource type: {resource_type}'}
            
    except Exception as e:
        return False, {'error': str(e)}

def test_ec2_instance(resource_id):
    """EC2インスタンスの匿名アクセステスト"""
    
    try:
        ec2 = boto3.client('ec2')
        instance_id = resource_id.split('/')[-1]
        
        response = ec2.describe_instances(InstanceIds=[instance_id])
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                public_ip = instance.get('PublicIpAddress')
                
                if not public_ip:
                    return False, {'message': 'No public IP address'}
                
                # HTTP/HTTPSテスト
                for protocol in ['http', 'https']:
                    if test_http_url(f"{protocol}://{public_ip}"):
                        return True, {
                            'accessible_endpoint': f"{protocol}://{public_ip}",
                            'method': 'HTTP'
                        }
                
                # TCPポートテスト
                for port in [22, 80, 443, 3389]:
                    if test_tcp_port(public_ip, port):
                        return True, {
                            'accessible_endpoint': f"{public_ip}:{port}",
                            'method': 'TCP'
                        }
        
        return False, {'message': 'No accessible endpoints found'}
        
    except Exception as e:
        return False, {'error': str(e)}

def test_rds_instance(resource_id):
    """RDSインスタンスの匿名アクセステスト"""
    
    try:
        rds = boto3.client('rds')
        db_identifier = resource_id.split(':')[-1]
        
        response = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
        
        for db_instance in response['DBInstances']:
            if not db_instance.get('PubliclyAccessible', False):
                return False, {'message': 'Not publicly accessible'}
            
            endpoint = db_instance.get('Endpoint', {})
            address = endpoint.get('Address')
            port = endpoint.get('Port', 3306)
            
            if address and test_tcp_port(address, port):
                return True, {
                    'accessible_endpoint': f"{address}:{port}",
                    'method': 'TCP'
                }
        
        return False, {'message': 'Database not accessible'}
        
    except Exception as e:
        return False, {'error': str(e)}

def test_s3_bucket(resource_id):
    """S3バケットの匿名アクセステスト"""
    
    try:
        bucket_name = resource_id.split(':')[-1]
        
        test_urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/"
        ]
        
        for url in test_urls:
            if test_http_url(url):
                return True, {
                    'accessible_endpoint': url,
                    'method': 'HTTP'
                }
        
        return False, {'message': 'Bucket not anonymously accessible'}
        
    except Exception as e:
        return False, {'error': str(e)}

def test_lambda_function(resource_id):
    """Lambda関数の匿名アクセステスト"""
    
    try:
        lambda_client = boto3.client('lambda')
        function_name = resource_id.split(':')[-1]
        
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=function_name)
            function_url = url_config.get('FunctionUrl')
            
            if function_url and test_http_url(function_url):
                return True, {
                    'accessible_endpoint': function_url,
                    'method': 'HTTP'
                }
        except lambda_client.exceptions.ResourceNotFoundException:
            pass
        
        return False, {'message': 'No public Function URL configured'}
        
    except Exception as e:
        return False, {'error': str(e)}

def test_ecs_service(resource_id):
    """ECSサービスの匿名アクセステスト"""
    
    try:
        # ECSサービス自体は直接アクセスできない
        return False, {'message': 'ECS Service requires Load Balancer configuration'}
        
    except Exception as e:
        return False, {'error': str(e)}

def test_eks_cluster(resource_id):
    """EKSクラスターの匿名アクセステスト"""
    
    try:
        eks = boto3.client('eks')
        cluster_name = resource_id.split('/')[-1]
        
        response = eks.describe_cluster(name=cluster_name)
        endpoint = response['cluster'].get('endpoint')
        
        if endpoint and test_http_url(endpoint):
            return True, {
                'accessible_endpoint': endpoint,
                'method': 'HTTP'
            }
        
        return False, {'message': 'Kubernetes API not publicly accessible'}
        
    except Exception as e:
        return False, {'error': str(e)}

def test_dynamodb_table(resource_id):
    """DynamoDBテーブルの匿名アクセステスト"""
    
    # DynamoDBは直接匿名アクセス不可
    return False, {'message': 'DynamoDB does not support direct anonymous access'}

def test_iam_user(resource_id):
    """IAMユーザーの匿名アクセステスト"""
    
    # IAMユーザーは直接アクセス対象ではない
    return False, {'message': 'IAM User is not directly accessible'}

def test_tcp_port(host, port, timeout=5):
    """TCPポート接続テスト"""
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def test_http_url(url, timeout=5):
    """HTTP/HTTPS接続テスト"""
    
    try:
        import urllib.request
        import urllib.error
        import ssl
        
        # SSL証明書の検証を無効化
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return response.getcode() < 500
    except:
        return False

def send_sns_notification(results):
    """SNS通知送信"""
    
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if not sns_topic_arn:
        print("SNS_TOPIC_ARN not configured")
        return
    
    try:
        sns = boto3.client('sns')
        
        accessible_count = sum(1 for r in results if r['is_accessible'])
        total_count = len(results)
        
        # SNS用のメッセージ作成
        subject = f"Security Hub Exposure Alert: {accessible_count}件の匿名アクセス可能リソース"
        
        # メッセージ本文作成
        message_lines = [
            "🔒 Security Hub Exposure Finding Alert",
            f"実行時刻: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "📊 検査結果サマリー:",
            f"- 検査済みFindings: {total_count}件",
            f"- 匿名アクセス可能: {accessible_count}件",
            f"- アクセス不可: {total_count - accessible_count}件",
            ""
        ]
        
        # アクセス可能なリソースの詳細
        accessible_findings = [r for r in results if r['is_accessible']]
        
        if accessible_findings:
            message_lines.append("🚨 匿名アクセス可能なリソース:")
            message_lines.append("")
            
            for i, finding in enumerate(accessible_findings[:5], 1):  # 最大5件
                message_lines.append(f"{i}. {finding['title']} (重要度: {finding['severity']})")
                
                for test_result in finding['test_results']:
                    if test_result['is_accessible']:
                        resource_name = test_result['resource_id'].split('/')[-1]
                        endpoint = test_result['details'].get('accessible_endpoint', 'Unknown')
                        message_lines.append(f"   🎯 {test_result['resource_type']}: {resource_name}")
                        message_lines.append(f"   🔗 アクセス可能エンドポイント: {endpoint}")
                        message_lines.append("")
            
            if len(accessible_findings) > 5:
                message_lines.append(f"... 他 {len(accessible_findings) - 5}件のアクセス可能リソースがあります")
        else:
            message_lines.append("✅ 匿名アクセス可能なリソースは検出されませんでした")
        
        message_lines.extend([
            "",
            "📝 詳細情報:",
            "CloudWatch Logsでより詳細な情報を確認できます:",
            "/aws/lambda/SecurityHubExposureChecker",
            "",
            "Generated by AWS Security Hub Exposure Checker"
        ])
        
        message_body = "\n".join(message_lines)
        
        # SNSメッセージ送信
        response = sns.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message_body
        )
        
        print(f"SNS notification sent successfully. MessageId: {response['MessageId']}")
        return True
        
    except Exception as e:
        print(f"SNS notification error: {e}")
        return False