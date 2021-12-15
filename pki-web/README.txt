./gradlew bootJar bootRun --args='--spring.config.location=file:///example/ --spring.config.name=test'
java -jar pki-web.jar --spring.config.location=file:///example/ --spring.config.name=test