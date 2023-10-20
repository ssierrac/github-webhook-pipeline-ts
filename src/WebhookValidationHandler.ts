import { LambdaInterface } from '@aws-lambda-powertools/commons';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { logger, metrics, tracer } from './powertools';
import { log } from 'console';

const WEBHOOK_SECRET_NAME = process.env.WEBHOOK_SECRET_NAME;

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
        logger.info('Lambda invocation event', { event });
        logger.info(`Secret name ${WEBHOOK_SECRET_NAME}`);

        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Webhook validation successful',
            }),
        };
    }
}

export const myFunction = new ValidateWebhookFuntion();
export const lambdaHandler = myFunction.handler.bind(myFunction);
