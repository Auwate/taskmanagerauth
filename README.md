# Task Manager Auth

The authentication & authorization component to a task manager application. It features a structured REST API using Spring Boot built to manage operations on tasks.

# Development Instructions

## Running with Docker

To run the application with Docker, you need to run `docker build` and `docker run` on the provided Dockerfile.

## Running without Docker

To run without Docker, you need to first `build` the JAR file, which can be done with `mvn clean package`. This will run your tests, then package the JAR file. You then need to run `java -jar <JAR_FILE_NAME>` to run the application.

## Running all tests

To run all the tests, please run `mvn clean verify` to run all tests.

# Features

Features are constantly being pushed out, but the following contains the list of current and planned features:

## Current Features

- REST API Structure
- Customized exception handling and data transfer object responses
  - Includes the status code, message (including errors), timestamp, and data
- Fully-functional CI/CD pipeline to test & build, push the latest image, and deploy the image on an Oracle VM
- Unit & integration tests with simulate REST API interactions with an H2 database
- Cloud storage using Oracle SQL ADB (Autonomous database)
  - Automatic data removal after 72 hours of inactivity
- JWT for authentication

## Planned Features

- Actuator for live monitoring for DevOps
- Redis for caching current tasks

# Current Endpoints

## `/api/auth/login` - POST

Log in. On successful login it will return a JWT

## `/api/auth/register` - POST

Register. Does not return any data.
