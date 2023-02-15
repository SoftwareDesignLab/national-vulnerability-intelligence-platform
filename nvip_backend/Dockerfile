FROM maven:3.8-jdk-11-slim AS builder

WORKDIR /home/app

ADD sleepycat-5.0.84.jar .
RUN mvn install:install-file \
   -Dfile=sleepycat-5.0.84.jar \
   -DgroupId=com.sleepycat \
   -DartifactId=je \
   -Dversion=5.0.84 \
   -Dpackaging=jar \
   -DgeneratePom=true

ADD pom.xml .
ADD nvip_data nvip_data
ADD src src

RUN mvn clean package -Dmaven.test.skip=true

### Run Stage
FROM openjdk:11-jre-slim
COPY --from=builder /home/app/target/nvip-1.0.jar /usr/local/lib/nvip-1.0.jar

ENTRYPOINT ["java","-jar","/usr/local/lib/nvip-1.0.jar"]