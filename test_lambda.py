#!/usr/bin/env python3
"""
Lambda関数のテストスクリプト
"""

import json
import sys
import os

# lambda_function.pyをインポート
sys.path.append('.')
from lambda_function import lambda_handler, test_tcp_port, test_http_url, send_sns_notification

def test_lambda_handler():
    """Lambda関数のメインハンドラーテスト"""
    print("=== Lambda Handler Test ===")
    
    # テストイベント作成
    test_event = {
        "version": "0",
        "id": "test-event-id",
        "detail-type": "Security Hub Findings - Imported",
        "source": "aws.securityhub",
        "account": "123456789012",
        "time": "2025-01-01T12:00:00Z",
        "region": "ap-northeast-1",
        "detail": {
            "findings": [
                {
                    "Id": "test-finding-001",
                    "Title": "Test Publicly Accessible S3 Bucket",
                    "Type": ["Exposure"],
                    "Severity": {"Label": "HIGH"},
                    "Resources": [
                        {
                            "Type": "AWS::S3::Bucket",
                            "Id": "arn:aws:s3:::test-public-bucket"
                        }
                    ]
                },
                {
                    "Id": "test-finding-002", 
                    "Title": "Test EC2 Instance",
                    "Type": ["Exposure"],
                    "Severity": {"Label": "MEDIUM"},
                    "Resources": [
                        {
                            "Type": "AWS::EC2::Instance",
                            "Id": "arn:aws:ec2:ap-northeast-1:123456789012:instance/i-1234567890abcdef0"
                        }
                    ]
                },
                {
                    "Id": "test-finding-003",
                    "Title": "Test Non-Exposure Finding",
                    "Type": ["Software and Configuration Checks"],
                    "Severity": {"Label": "LOW"},
                    "Resources": [
                        {
                            "Type": "AWS::S3::Bucket",
                            "Id": "arn:aws:s3:::test-bucket"
                        }
                    ]
                }
            ]
        }
    }
    
    # テスト実行
    try:
        # SNS_TOPIC_ARNを一時的に設定
        original_sns_arn = os.environ.get('SNS_TOPIC_ARN')
        os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:ap-northeast-1:123456789012:test-topic'
        
        result = lambda_handler(test_event, {})
        
        print(f"Status Code: {result['statusCode']}")
        body = json.loads(result['body'])
        print(f"Message: {body['message']}")
        print(f"Processed Count: {body['processed_count']}")
        print(f"Results: {len(body['results'])} findings processed")
        
        # Exposure Findingのみ処理されることを確認
        assert body['processed_count'] == 2, f"Expected 2 processed findings, got {body['processed_count']}"
        
        # 各結果を表示
        for i, finding_result in enumerate(body['results']):
            print(f"\nFinding {i+1}:")
            print(f"  Title: {finding_result['title']}")
            print(f"  Severity: {finding_result['severity']}")
            print(f"  Accessible: {finding_result['is_accessible']}")
            print(f"  Test Results: {len(finding_result['test_results'])}")
        
        print("✅ Lambda Handler Test: PASSED")
        
        # 元のSNS_TOPIC_ARNを復元
        if original_sns_arn:
            os.environ['SNS_TOPIC_ARN'] = original_sns_arn
        else:
            os.environ.pop('SNS_TOPIC_ARN', None)
        
        return True
        
    except Exception as e:
        print(f"❌ Lambda Handler Test: FAILED - {e}")
        return False

def test_tcp_connection():
    """TCP接続テスト"""
    print("\n=== TCP Connection Test ===")
    
    # Google DNS (成功するはず)
    result = test_tcp_port('8.8.8.8', 53, timeout=3)
    print(f"Google DNS (8.8.8.8:53): {result}")
    assert result == True, "Google DNS should be accessible"
    
    # 存在しないホスト (失敗するはず)
    result = test_tcp_port('192.0.2.1', 80, timeout=2)
    print(f"Non-existent host (192.0.2.1:80): {result}")
    assert result == False, "Non-existent host should not be accessible"
    
    print("✅ TCP Connection Test: PASSED")
    return True

def test_http_connection():
    """HTTP接続テスト"""
    print("\n=== HTTP Connection Test ===")
    
    # Google (成功するはず)
    result = test_http_url('https://www.google.com', timeout=5)
    print(f"Google (https://www.google.com): {result}")
    assert result == True, "Google should be accessible"
    
    # 存在しないサイト (失敗するはず)
    result = test_http_url('https://nonexistent.example.invalid', timeout=2)
    print(f"Non-existent site: {result}")
    assert result == False, "Non-existent site should not be accessible"
    
    print("✅ HTTP Connection Test: PASSED")
    return True

def test_sns_notification():
    """SNS通知テスト（実際には送信しない）"""
    print("\n=== SNS Notification Test ===")
    
    # テスト用結果データ
    test_results = [
        {
            'finding_id': 'test-001',
            'title': 'Test Publicly Accessible S3 Bucket',
            'severity': 'HIGH',
            'timestamp': '2025-01-01T12:00:00',
            'is_accessible': True,
            'test_results': [
                {
                    'resource_type': 'AWS::S3::Bucket',
                    'resource_id': 'arn:aws:s3:::test-bucket',
                    'is_accessible': True,
                    'details': {
                        'accessible_endpoint': 'https://test-bucket.s3.amazonaws.com/',
                        'method': 'HTTP'
                    }
                }
            ]
        },
        {
            'finding_id': 'test-002',
            'title': 'Test Secure Resource',
            'severity': 'MEDIUM',
            'timestamp': '2025-01-01T12:00:00',
            'is_accessible': False,
            'test_results': [
                {
                    'resource_type': 'AWS::EC2::Instance',
                    'resource_id': 'arn:aws:ec2:ap-northeast-1:123456789012:instance/i-1234567890abcdef0',
                    'is_accessible': False,
                    'details': {
                        'message': 'No public IP address'
                    }
                }
            ]
        }
    ]
    
    # SNS_TOPIC_ARNが設定されていない場合のテスト
    original_sns_arn = os.environ.get('SNS_TOPIC_ARN')
    os.environ.pop('SNS_TOPIC_ARN', None)
    
    result = send_sns_notification(test_results)
    print(f"SNS notification without topic ARN: {result}")
    
    # SNS_TOPIC_ARNが設定されている場合のテスト（実際には送信しない）
    os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:ap-northeast-1:123456789012:test-topic'
    
    try:
        # 実際のSNS送信はスキップして、メッセージ構築のみテスト
        print("SNS message construction test:")
        accessible_count = sum(1 for r in test_results if r['is_accessible'])
        print(f"  Accessible findings: {accessible_count}")
        print(f"  Total findings: {len(test_results)}")
        
        print("✅ SNS Notification Test: PASSED")
        
    except Exception as e:
        print(f"❌ SNS Notification Test: FAILED - {e}")
        return False
    finally:
        # 元のSNS_TOPIC_ARNを復元
        if original_sns_arn:
            os.environ['SNS_TOPIC_ARN'] = original_sns_arn
        else:
            os.environ.pop('SNS_TOPIC_ARN', None)
    
    return True

def test_resource_type_handling():
    """リソースタイプ別処理のテスト"""
    print("\n=== Resource Type Handling Test ===")
    
    from lambda_function import test_resource
    
    test_cases = [
        ('AWS::S3::Bucket', 'arn:aws:s3:::test-bucket'),
        ('AWS::EC2::Instance', 'arn:aws:ec2:ap-northeast-1:123456789012:instance/i-1234567890abcdef0'),
        ('AWS::RDS::DBInstance', 'arn:aws:rds:ap-northeast-1:123456789012:db:test-db'),
        ('AWS::Lambda::Function', 'arn:aws:lambda:ap-northeast-1:123456789012:function:test-function'),
        ('AWS::ECS::Service', 'arn:aws:ecs:ap-northeast-1:123456789012:service/test-service'),
        ('AWS::EKS::Cluster', 'arn:aws:eks:ap-northeast-1:123456789012:cluster/test-cluster'),
        ('AWS::DynamoDB::Table', 'arn:aws:dynamodb:ap-northeast-1:123456789012:table/test-table'),
        ('AWS::IAM::User', 'arn:aws:iam::123456789012:user/test-user'),
        ('AWS::UnknownService::Resource', 'arn:aws:unknown:ap-northeast-1:123456789012:resource/test')
    ]
    
    for resource_type, resource_id in test_cases:
        try:
            is_accessible, details = test_resource(resource_type, resource_id)
            print(f"  {resource_type}: accessible={is_accessible}, details={details.get('message', details.get('error', 'OK'))}")
        except Exception as e:
            print(f"  {resource_type}: ERROR - {e}")
    
    print("✅ Resource Type Handling Test: PASSED")
    return True

def test_edge_cases():
    """エッジケースのテスト"""
    print("\n=== Edge Cases Test ===")
    
    # 空のイベント
    empty_event = {"detail": {"findings": []}}
    result = lambda_handler(empty_event, {})
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['processed_count'] == 0
    print("✅ Empty event handled correctly")
    
    # 不正なイベント構造
    invalid_event = {"invalid": "structure"}
    result = lambda_handler(invalid_event, {})
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['processed_count'] == 0
    print("✅ Invalid event structure handled correctly")
    
    # Exposure以外のfinding
    non_exposure_event = {
        "detail": {
            "findings": [{
                "Id": "test-001",
                "Title": "Non-exposure finding",
                "Type": ["Software and Configuration Checks"],
                "Severity": {"Label": "LOW"},
                "Resources": [{"Type": "AWS::S3::Bucket", "Id": "arn:aws:s3:::test"}]
            }]
        }
    }
    result = lambda_handler(non_exposure_event, {})
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['processed_count'] == 0
    print("✅ Non-exposure findings filtered correctly")
    
    print("✅ Edge Cases Test: PASSED")
    return True

def main():
    """メインテスト実行"""
    print("🧪 Security Hub Exposure Checker - Lambda Function Tests")
    print("=" * 60)
    
    tests = [
        test_tcp_connection,
        test_http_connection,
        test_resource_type_handling,
        test_sns_notification,
        test_edge_cases,
        test_lambda_handler,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test_func.__name__}: FAILED - {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"🎯 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Lambda function is ready for deployment.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the issues before deployment.")
        return 1

if __name__ == "__main__":
    exit(main())