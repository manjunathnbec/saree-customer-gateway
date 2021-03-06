FROM openjdk:8-jdk-alpine
ARG JAR_FILE
COPY ${JAR_FILE} service.jar
ENTRYPOINT ["java", "-jar", "/service.jar"]