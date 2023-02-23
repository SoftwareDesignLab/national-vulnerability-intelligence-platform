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
RUN mvn dependency:go-offline
ADD src/main src/main

RUN mvn package -Dmaven.test.skip=true

### Run Stage
FROM openjdk:11-jre-slim

ADD nvip_data /usr/local/lib/nvip_data
COPY --from=builder /home/app/target/nvip_lib /usr/local/lib/nvip_lib
COPY --from=builder /home/app/target/nvip-1.0.jar /usr/local/lib/nvip-1.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "nvip-1.0.jar:nvip_lib/*", "edu.rit.se.nvip.NVIPMain"]
