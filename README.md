# github-webhook-pipeline-ts

Congratulations, you have just created a Serverless "Hello World" application using the AWS Serverless Application Model (AWS SAM) for the `nodejs18.x` runtime, and options to bootstrap it with [**Powertools for AWS Lambda (TypeScript)**](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/) (Lambda Powertools) utilities for Logging, Tracing and Metrics.

Powertools for AWS Lambda (TypeScript) is a developer toolkit to implement Serverless best practices and increase developer velocity.

## Powertools for AWS Lambda (TypeScript) features

Powertools for AWS Lambda (TypeScript) provides three core utilities:

* **[Tracer](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/core/tracer/)** - Utilities to trace Lambda function handlers, and both synchronous and asynchronous functions
* **[Logger](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/core/logger/)** - Structured logging made easier, and a middleware to enrich log items with key details of the Lambda context
* **[Metrics](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/core/metrics/)** - Custom Metrics created asynchronously via CloudWatch Embedded Metric Format (EMF)

Find the complete project's [documentation here](https://awslabs.github.io/aws-lambda-powertools-typescript).

### Installing Powertools for AWS Lambda (TypeScript)

You have 2 ways of consuming those utilities:

* NPM modules
* Lambda Layer

#### Lambda layers

The Powertools for AWS Lambda (TypeScript) utilities is packaged as a single [AWS Lambda Layer](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-concepts.html#gettingstarted-concepts-layer)

👉 [Installation guide for the **Powertools for AWS Lambda (TypeScript)** layer](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/#lambda-layer)

#### NPM modules

The Powertools for AWS Lambda (TypeScript) utilities follow a modular approach, similar to the official [AWS SDK v3 for JavaScript](https://github.com/aws/aws-sdk-js-v3).  

Each TypeScript utility is installed as standalone NPM package.

Install all three core utilities at once with this single command:

```shell
npm install @aws-lambda-powertools/logger @aws-lambda-powertools/tracer @aws-lambda-powertools/metrics
```

Or refer to the installation guide of each utility:

👉 [Installation guide for the **Tracer** utility](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/core/tracer#getting-started)

👉 [Installation guide for the **Logger** utility](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/core/logger#getting-started)

👉 [Installation guide for the **Metrics** utility](https://awslabs.github.io/aws-lambda-powertools-typescript/latest/core/metrics#getting-started)

### Powertools for AWS Lambda (TypeScript) Examples

* [CDK](https://github.com/awslabs/aws-lambda-powertools-typescript/tree/main/examples/cdk)
* [SAM](https://github.com/awslabs/aws-lambda-powertools-typescript/tree/main/examples/sam)

## Working with this project

This project contains source code and supporting files for a serverless application that you can deploy with the SAM CLI. It includes the following files and folders.

* hello-world - Code for the application's Lambda function written in TypeScript.
* events - Invocation events that you can use to invoke the function.
* hello-world/tests - Unit tests for the application code.
* template.yaml - A template that defines the application's AWS resources.

The application uses several AWS resources, including Lambda functions and an API Gateway API. These resources are defined in the `template.yaml` file in this project. You can update the template to add AWS resources through the same deployment process that updates your application code.

If you prefer to use an integrated development environment (IDE) to build and test your application, you can use the AWS Toolkit.  
The AWS Toolkit is an open source plug-in for popular IDEs that uses the SAM CLI to build and deploy serverless applications on AWS. The AWS Toolkit also adds a simplified step-through debugging experience for Lambda function code. See the following links to get started.

* [CLion](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [GoLand](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [IntelliJ](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [WebStorm](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [Rider](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [PhpStorm](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [PyCharm](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [RubyMine](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [DataGrip](https://docs.aws.amazon.com/toolkit-for-jetbrains/latest/userguide/welcome.html)
* [VS Code](https://docs.aws.amazon.com/toolkit-for-vscode/latest/userguide/welcome.html)
* [Visual Studio](https://docs.aws.amazon.com/toolkit-for-visual-studio/latest/user-guide/welcome.html)

### Deploy the sample application

The Serverless Application Model Command Line Interface (SAM CLI) is an extension of the AWS CLI that adds functionality for building and testing Lambda applications. It uses Docker to run your functions in an Amazon Linux environment that matches Lambda. It can also emulate your application's build environment and API.

To use the SAM CLI, you need the following tools.

* SAM CLI - [Install the SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
* Node.js - [Install Node.js 18](https://nodejs.org/en/), including the NPM package management tool.
* Docker - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community)

To build and deploy your application for the first time, run the following in your shell:

```bash
sam build
sam deploy --guided
```

The first command will build the source of your application. The second command will package and deploy your application to AWS, with a series of prompts:

* **Stack Name**: The name of the stack to deploy to CloudFormation. This should be unique to your account and region, and a good starting point would be something matching your project name.
* **AWS Region**: The AWS region you want to deploy your app to.
* **Confirm changes before deploy**: If set to yes, any change sets will be shown to you before execution for manual review. If set to no, the AWS SAM CLI will automatically deploy application changes.
* **Allow SAM CLI IAM role creation**: Many AWS SAM templates, including this example, create AWS IAM roles required for the AWS Lambda function(s) included to access AWS services. By default, these are scoped down to minimum required permissions. To deploy an AWS CloudFormation stack which creates or modifies IAM roles, the `CAPABILITY_IAM` value for `capabilities` must be provided. If permission isn't provided through this prompt, to deploy this example you must explicitly pass `--capabilities CAPABILITY_IAM` to the `sam deploy` command.
* **Save arguments to samconfig.toml**: If set to yes, your choices will be saved to a configuration file inside the project, so that in the future you can just re-run `sam deploy` without parameters to deploy changes to your application.

You can find your API Gateway Endpoint URL in the output values displayed after deployment.

### Use the SAM CLI to build and test locally

Build your application with the `sam build` command.

```bash
github-webhook-pipeline-ts$ sam build
```

The SAM CLI installs dependencies defined in `hello-world/package.json`, compiles TypeScript with esbuild, creates a deployment package, and saves it in the `.aws-sam/build` folder.

Test a single function by invoking it directly with a test event. An event is a JSON document that represents the input that the function receives from the event source. Test events are included in the `events` folder in this project.

Run functions locally and invoke them with the `sam local invoke` command.

```bash
github-webhook-pipeline-ts$ sam local invoke HelloWorldFunction --event events/event.json
```

The SAM CLI can also emulate your application's API. Use the `sam local start-api` to run the API locally on port 3000.

```bash
github-webhook-pipeline-ts$ sam local start-api
github-webhook-pipeline-ts$ curl http://localhost:3000/
```

The SAM CLI reads the application template to determine the API's routes and the functions that they invoke. The `Events` property on each function's definition includes the route and method for each path.

```yaml
      Events:
        HelloWorld:
          Type: Api
          Properties:
            Path: /hello
            Method: get
```

### Add a resource to your application

The application template uses AWS Serverless Application Model (AWS SAM) to define application resources. AWS SAM is an extension of AWS CloudFormation with a simpler syntax for configuring common serverless application resources such as functions, triggers, and APIs. For resources not included in [the SAM specification](https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md), you can use standard [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html) resource types.

### Fetch, tail, and filter Lambda function logs

To simplify troubleshooting, SAM CLI has a command called `sam logs`. `sam logs` lets you fetch logs generated by your deployed Lambda function from the command line. In addition to printing the logs on the terminal, this command has several nifty features to help you quickly find the bug.

`NOTE`: This command works for all AWS Lambda functions; not just the ones you deploy using SAM.

```bash
github-webhook-pipeline-ts$ sam logs -n HelloWorldFunction --stack-name github-webhook-pipeline-ts --tail
```

You can find more information and examples about filtering Lambda function logs in the [SAM CLI Documentation](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-logging.html).

### Unit tests

Tests are defined in the `test` folder in this project.

```bash
github-webhook-pipeline-ts$ cd hello-world
hello-world$ npm install
hello-world$ npm run test
```

### Cleanup

To delete the sample application that you created, use the AWS CLI. Assuming you used your project name for the stack name, you can run the following:

```bash
sam delete --stack-name github-webhook-pipeline-ts
```

## Resources

See the [AWS SAM developer guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html) for an introduction to SAM specification, the SAM CLI, and serverless application concepts.

Next, you can use AWS Serverless Application Repository to deploy ready to use Apps that go beyond hello world samples and learn how authors developed their applications: [AWS Serverless Application Repository main page](https://aws.amazon.com/serverless/serverlessrepo/)
