### Build Stage
FROM maven:3.8-jdk-11-slim AS builder

WORKDIR /home/app

ADD pom.xml .
RUN mvn dependency:go-offline
ADD docker.context.xml WebContent/META-INF/context.xml
ADD src/main src/main
ADD WebContent WebContent/

RUN mvn package -Dmaven.test.skip=true

### Run Stage
FROM tomcat:9.0-alpine as deploy

RUN rm -r /usr/local/tomcat/webapps/ROOT
COPY --from=builder /home/app/target/nvip_ui-1.0.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080
CMD ["catalina.sh", "run"]