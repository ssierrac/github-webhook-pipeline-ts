/* eslint-disable @typescript-eslint/no-non-null-assertion */
import * as crypto from 'crypto';
import { logger, metrics, tracer } from './powertools';
import { LambdaInterface } from '@aws-lambda-powertools/commons';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';

const WEBHOOK_SECRET_NAME = process.env.WEBHOOK_SECRET_NAME;
const SNS_TOPIC = process.env.SNS_TOPIC;
const sm_client = new SecretsManagerClient();
const sns_client = new SNSClient();
class ValidateWebhookFuntion implements LambdaInterface {
    /**
     * Handle the github webhook validation.
     * @param {APIGatewayProxyEvent} event - API Gateway Lambda Proxy Input Format
     * @returns {APIGatewayProxyResult} object - API Gateway Lambda Proxy Output Format
     *
     */
    @tracer.captureLambdaHandler()
    @metrics.logMetrics({ captureColdStartMetric: true })
    @logger.injectLambdaContext({ logEvent: true })
    public async handler(event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> {
        try {
            if (!WEBHOOK_SECRET_NAME) {
                throw new Error('WEBHOOK_SECRET_NAME is not defined');
            }

            const secret = await this.getSecret(WEBHOOK_SECRET_NAME);
            if (!secret || !this.verifySignature(event, secret)) {
                throw new Error('Signature verification failed');
            }
            if (event.body === null) {
                throw new Error('Body is null');
            }
            const body = JSON.parse(event.body);
            logger.info(`Signature verification successful for ${body.repository.full_name} repo`);
            logger.info(`Payload received`, body);

            const response = await this.publishPayload(body);
            return {
                statusCode: 200,
                body: JSON.stringify({
                    message: 'Webhook validation successful',
                    messageId: response.MessageId,
                }),
            };
        } catch (err) {
            tracer.addErrorAsMetadata(err as Error);
            logger.error('Error validating webhook', err as Error);
            if (err == 'Signature verification failed') {
                return {
                    statusCode: 401,
                    body: JSON.stringify({
                        message: 'Webhook validation failed, unauthorized',
                    }),
                };
            }
            return {
                statusCode: 400,
                body: JSON.stringify({
                    message: 'Webhook validation failed',
                }),
            };
        }
    }

    // Get secrete value from secretes manager
    private async getSecret(secretName: string) {
        try {
            const command = new GetSecretValueCommand({ SecretId: secretName });
            const response = await sm_client.send(command);
            return response.SecretString;
        } catch (err) {
            logger.error(`Error getting secret ${secretName} from Secrets Manager`);
            throw err;
        }
    }

    private verifySignature(event: APIGatewayProxyEvent, secret: string) {
        const signature = crypto.createHmac('sha256', secret).update(event.body!).digest('hex');
        const trusted = Buffer.from(`sha256=${signature}`, 'ascii');
        const untrusted = Buffer.from(event.headers['X-Hub-Signature-256']!, 'ascii');
        return crypto.timingSafeEqual(trusted, untrusted);
    }

    private async publishPayload(payload: any) {
        try {
            const message = {
                default: `Push event received for ${payload.repository.full_name} repo`,
                lambda: payload,
            };

            const command = new PublishCommand({
                Message: JSON.stringify(message),
                MessageStructure: 'json',
                TopicArn: SNS_TOPIC,
            });
            const response = await sns_client.send(command);
            logger.info(`Payload published to SNS topic ${SNS_TOPIC}`);
            return response;
        } catch (err) {
            logger.error(`Error publishing payload to SNS topic ${SNS_TOPIC}`);
            throw err;
        }
    }
}

export const myFunction = new ValidateWebhookFuntion();
export const lambdaHandler = myFunction.handler.bind(myFunction);
