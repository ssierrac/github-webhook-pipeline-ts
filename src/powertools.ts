import { Metrics } from '@aws-lambda-powertools/metrics';
import { Logger } from '@aws-lambda-powertools/logger';
import type { LogLevel } from '@aws-lambda-powertools/logger/lib/types';
import { Tracer } from '@aws-lambda-powertools/tracer';

// Set up the globals
const SERVICE_NAMESPACE = process.env.SERVICE_NAMESPACE ?? 'test_namespace';

const defaultValues = {
    region: process.env.AWS_REGION || 'N/A',
    executionEnv: process.env.AWS_EXECUTION_ENV || 'N/A',
};

const logger = new Logger({
    logLevel: (process.env.LOG_LEVEL || 'INFO') as LogLevel,
    persistentLogAttributes: {
        ...defaultValues,
        logger: {
            name: '@aws-lambda-powertools/logger',
        },
    },
});

const metrics = new Metrics({
    defaultDimensions: defaultValues,
    namespace: SERVICE_NAMESPACE,
});

const tracer = new Tracer();

export { metrics, logger, tracer };
