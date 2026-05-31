FROM webgoat/webgoat:latest

COPY --chown=webgoat:webgoat rasp /opt/rasp

ENV JAVA_TOOL_OPTIONS="--add-opens=java.base/jdk.internal.loader=ALL-UNNAMED -javaagent:/opt/rasp/rasp.jar"

EXPOSE 8080
