./gradlew bootJar bootRun --args='--spring.config.location=file:///example/ --spring.config.name=test'
java -jar pki-api.jar --spring.config.location=file:///example/ --spring.config.name=test