#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
: "${ZEROTH_AWS_AUDIENCE:?Set ZEROTH_AWS_AUDIENCE}"
: "${ZEROTH_AWS_CLIENT_ID:?Set ZEROTH_AWS_CLIENT_ID}"
: "${ZEROTH_AWS_ISSUER:?Set ZEROTH_AWS_ISSUER}"
region="${ZEROTH_AWS_REGION:-us-east-1}"
name="${ZEROTH_AWS_NAME:-zeroth-authorizer-${ZEROTH_AWS_AUDIENCE,,}}"
artifacts_stack="${ZEROTH_AWS_ARTIFACTS_STACK:-zeroth-lambda-artifacts}"
authorizer_stack="${ZEROTH_AWS_STACK:-$name}"

aws cloudformation deploy --region "$region" --stack-name "$artifacts_stack" \
  --template-file deploy/aws/artifacts.yml --no-fail-on-empty-changeset
bucket="$(aws cloudformation describe-stacks --region "$region" --stack-name "$artifacts_stack" \
  --query 'Stacks[0].Outputs[?OutputKey==`BucketName`].OutputValue' --output text)"
bash deploy/aws/package.sh build/zeroth-authorizer.zip >/dev/null
digest="$(shasum -a 256 build/zeroth-authorizer.zip | cut -d ' ' -f 1)"
key="authorizers/${digest}.zip"
aws s3api put-object --region "$region" --bucket "$bucket" --key "$key" \
  --body build/zeroth-authorizer.zip --if-none-match '*' >/dev/null || \
  aws s3api head-object --region "$region" --bucket "$bucket" --key "$key" >/dev/null
aws cloudformation deploy --region "$region" --stack-name "$authorizer_stack" \
  --template-file deploy/aws/authorizer.yml --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset --parameter-overrides \
  CodeBucket="$bucket" CodeKey="$key" FunctionName="$name" \
  Issuer="$ZEROTH_AWS_ISSUER" JwksUrl="${ZEROTH_AWS_JWKS_URL:-${ZEROTH_AWS_ISSUER}/.well-known/jwks.json}" \
  Audience="$ZEROTH_AWS_AUDIENCE" ClientId="$ZEROTH_AWS_CLIENT_ID"
aws cloudformation describe-stacks --region "$region" --stack-name "$authorizer_stack" \
  --query 'Stacks[0].Outputs[?OutputKey==`AuthorizerArn`].OutputValue' --output text
