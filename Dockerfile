# === Build stage ===
FROM maven:3.9.9-eclipse-temurin-21-alpine AS builder

WORKDIR /app

COPY pom.xml ./
COPY ./src ./src

RUN mvn clean package -DskipTests

# === Extract and run into minimal size ===

FROM eclipse-temurin:21.0.5_11-jre-alpine-3.21

WORKDIR /app

COPY --from=builder /app/target/*.jar ./app.jar

EXPOSE 9095

CMD ["java", "-jar", "app.jar"]