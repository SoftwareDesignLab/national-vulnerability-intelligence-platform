FROM maven:3.8-jdk-11 as builder

ADD pom.xml .
ADD .project .
ADD .classpath .
ADD src/ src/
ADD WebContent WebContent/

ADD docker.context.xml WebContent/META-INF/context.xml

RUN mvn clean package -Dskiptests

FROM tomcat:9.0-alpine as deploy

COPY --from=builder /target/nvip_ui-1.0.war /usr/local/tomcat/webapps

EXPOSE 8080
CMD ["catalina.sh", "run"]