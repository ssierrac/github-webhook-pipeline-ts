/* eslint-disable @typescript-eslint/no-non-null-assertion */
import * as crypto from 'crypto';
import { logger, metrics, tracer } from './powertools';
import { LambdaInterface } from '@aws-lambda-powertools/commons';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const WEBHOOK_SECRET_NAME = process.env.WEBHOOK_SECRET_NAME;
const client = new SecretsManagerClient();
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
            logger.info(body);
            return {
                statusCode: 200,
                body: JSON.stringify({
                    message: 'Webhook validation successful',
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
            const response = await client.send(command);
            return response.SecretString;
        } catch (err) {
            logger.error(`Error getting secret ${secretName} from Secrets Manager`);
            throw err;
        }
    }

    private verifySignature(event: APIGatewayProxyEvent, secret: string) {
        const signature = crypto.createHmac('sha256', secret).update(JSON.stringify(event.body)).digest('hex');
        const trusted = Buffer.from(`sha256=${signature}`, 'ascii');
        const untrusted = Buffer.from(event.headers['X-Hub-Signature-256']!, 'ascii');
        return crypto.timingSafeEqual(trusted, untrusted);
    }
}

export const myFunction = new ValidateWebhookFuntion();
export const lambdaHandler = myFunction.handler.bind(myFunction);
