#!/bin/bash

# Security Hub Exposure Checker - Terraform デプロイスクリプト

set -e

REGION="${AWS_DEFAULT_REGION:-ap-northeast-1}"

echo "🚀 Security Hub Exposure Checker (Terraform) デプロイ開始"

# SNS Topic ARN確認
if [ -z "$SNS_TOPIC_ARN" ]; then
    echo "❌ SNS_TOPIC_ARN環境変数が設定されていません"
    echo "例: export SNS_TOPIC_ARN='arn:aws:sns:ap-northeast-1:123456789012:security-alerts'"
    exit 1
fi

echo "✅ SNS Topic ARN: 設定済み"
echo "📍 Region: $REGION"

# terraform.tfvarsファイル作成
echo "📝 terraform.tfvarsファイル作成中..."
cat > terraform.tfvars << EOF
sns_topic_arn = "$SNS_TOPIC_ARN"
lambda_timeout = 60
lambda_memory_size = 256
log_retention_days = 7
EOF

echo "✅ terraform.tfvarsファイル作成完了"

# Terraformの初期化
if [ ! -d ".terraform" ]; then
    echo "🔧 Terraform初期化中..."
    terraform init
    echo "✅ Terraform初期化完了"
fi

# Terraformプランの確認
echo "📋 Terraformプラン確認中..."
terraform plan

# ユーザー確認
echo
read -p "📝 上記のプランでデプロイしますか？ (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ デプロイが中止されました"
    exit 1
fi

# Terraformデプロイ実行
echo "🚀 Terraformデプロイ実行中..."
terraform apply -auto-approve

echo "✅ Terraformデプロイ完了"

# 出力値を取得
LAMBDA_FUNCTION_NAME=$(terraform output -raw lambda_function_name)
LAMBDA_FUNCTION_ARN=$(terraform output -raw lambda_function_arn)
EVENTBRIDGE_RULE_NAME=$(terraform output -raw eventbridge_rule_name)

echo "📋 デプロイされたリソース:"
echo "  Lambda Function: $LAMBDA_FUNCTION_NAME"
echo "  Lambda Function ARN: $LAMBDA_FUNCTION_ARN"
echo "  EventBridge Rule: $EVENTBRIDGE_RULE_NAME"

# テスト実行
echo "🧪 Lambda関数テスト実行中..."

cat > test-event.json << EOF
{
  "version": "0",
  "id": "test-event",
  "detail-type": "Security Hub Findings - Imported",
  "source": "aws.securityhub",
  "account": "123456789012",
  "time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "region": "$REGION",
  "detail": {
    "findings": [
      {
        "Id": "test-finding-001",
        "Title": "Test Exposure Finding",
        "Type": ["Exposure"],
        "Severity": {"Label": "HIGH"},
        "Resources": [
          {
            "Type": "AWS::S3::Bucket", 
            "Id": "arn:aws:s3:::test-public-bucket"
          }
        ]
      }
    ]
  }
}
EOF

aws lambda invoke \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --payload file://test-event.json \
    --region "$REGION" \
    test-response.json > /dev/null 2>&1

echo "✅ テスト実行完了"
echo "📄 テスト結果:"
if command -v jq > /dev/null 2>&1; then
    cat test-response.json | jq .
else
    cat test-response.json | python -m json.tool 2>/dev/null || cat test-response.json
fi
echo

# クリーンアップ
rm -f test-event.json test-response.json

echo "🎉 デプロイ完了！"
echo
echo "🔍 確認方法:"
echo "  1. Security HubでExposure Findingが生成されると自動実行されます"
echo "  2. ログ確認: aws logs tail /aws/lambda/$LAMBDA_FUNCTION_NAME --follow --region $REGION"
echo "  3. SNS Topicに通知が送信されます（Amazon Q Developerに転送されTeamsに通知）"
echo
echo "🧪 追加テスト:"
echo "  python test_lambda.py"
echo
echo "🗑️  削除方法:"
echo "  terraform destroy"